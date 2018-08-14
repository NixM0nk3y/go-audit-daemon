// +build linux

package main

import (
    "os"
    "flag"
    "fmt"
    "time"
    "sync"
    "runtime"
    "strconv"
    "strings"
    "syscall"
    "github.com/pkg/errors"
    "github.com/golang/glog"
    "github.com/elastic/go-libaudit"
    "github.com/elastic/go-libaudit/aucoalesce"
    "github.com/elastic/go-libaudit/auparse"
)

const (
        auditLocked = 2

        unicast   = "unicast"
        multicast = "multicast"

        lostEventsUpdateInterval        = time.Second * 15
        maxDefaultStreamBufferConsumers = 4

        bsKernel backpressureStrategy = 1 << iota
        bsUserSpace
        bsAuto
)

type backpressureStrategy uint8

type AuditSet struct {
        config     Config
        client     *libaudit.AuditClient
        kernelLost struct {
                enabled bool
                counter uint32
        }
        backpressureStrategy backpressureStrategy
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: example -stderrthreshold=[INFO|WARN|FATAL] -log_dir=[string]\n", )
	flag.PrintDefaults()
	os.Exit(2)
}

func init() {
	flag.Usage = usage
	flag.Parse()
}

func main() {

    config := defaultConfig

    _, _, kernel, _ := kernelVersion()

    glog.Infof("auditd module is running as euid=%v on kernel=%v", os.Geteuid(), kernel)

    client, err := newAuditClient(&config)

    if err != nil {
        glog.Error("Failed to create new audit client")
	os.Exit(2)
    }

    defer client.Close()

    as := &AuditSet{
        client: client,
        config: config,
        backpressureStrategy: getBackpressureStrategy(config.BackpressureStrategy),
    }

    status, err := client.GetStatus()
    if err != nil {
        glog.Error("failed to get audit status")
        os.Exit(2)
    }

    glog.Infof("received audit status=%+v", status)

    done := make(chan struct{})
    defer close(done)

    out, err := receiveEvents(as, done)
    if err != nil {
        glog.Error("Failure receiving audit events")
        return
    }

    if as.kernelLost.enabled {

        client, err := libaudit.NewAuditClient(nil)
        if err != nil {
            glog.Errorln("Failure creating audit monitoring client", "error", err)
        }
        go func() {
            defer client.Close()
            timer := time.NewTicker(lostEventsUpdateInterval)
            defer timer.Stop()
            for {
                select {
                    case <-done:
                        return
                    case <-timer.C:
                        if status, err := client.GetStatus(); err == nil {
                            updateKernelLostMetric(as, status.Lost)
                        } else {
                            glog.Error("get status request failed:", err)
                        }
                }
            }
        }()
    }

    // Spawn the stream buffer consumers
    numConsumers := as.config.StreamBufferConsumers

    // By default (stream_buffer_consumers=0) use as many consumers as local CPUs
    // with a max of `maxDefaultStreamBufferConsumers`
    if numConsumers == 0 {
        if numConsumers = runtime.GOMAXPROCS(-1); numConsumers > maxDefaultStreamBufferConsumers {
            numConsumers = maxDefaultStreamBufferConsumers
        }
    }
    var wg sync.WaitGroup
    wg.Add(numConsumers)

    for i := 0; i < numConsumers; i++ {
        go func() {
            defer wg.Done()
            for {
                select {
                    case <-done:
                        return
                    case msgs := <-out:
                        buildEvent(msgs, as.config)
                }
            }
        }()
    }
    wg.Wait()

    return
}

func buildEvent(msgs []*auparse.AuditMessage, config Config) {

    auditEvent, err := aucoalesce.CoalesceMessages(msgs)

        if err != nil {
                glog.Error("Failure to CoalesceMessages events")
                return
        }

        if config.ResolveIDs {
                aucoalesce.ResolveIDs(auditEvent)
        }

}

func receiveEvents(as *AuditSet, done <-chan struct{}) (<-chan []*auparse.AuditMessage, error) {

    if err := initClient(as); err != nil {
        return nil, err
    }

    out := make(chan []*auparse.AuditMessage, as.config.StreamBufferQueueSize)

    return out, nil
}

func initClient(as *AuditSet) error {
        if as.config.SocketType == "multicast" {
                // This request will fail with EPERM if this process does not have
                // CAP_AUDIT_CONTROL, but we will ignore the response. The user will be
                // required to ensure that auditing is enabled if the process is only
                // given CAP_AUDIT_READ.
        }

        // Unicast client initialization (requires CAP_AUDIT_CONTROL and that the
        // process be in initial PID namespace).
        status, err := as.client.GetStatus()
        if err != nil {
                return errors.Wrap(err, "failed to get audit status")
        }
        as.kernelLost.enabled = true
        as.kernelLost.counter = status.Lost

        glog.Infoln("audit status from kernel at start", "audit_status", status)

        if status.Enabled == auditLocked {
                return errors.New("failed to configure: The audit system is locked")
        }

        if fm, _ := as.config.failureMode(); status.Failure != fm {
                if err = as.client.SetFailure(libaudit.FailureMode(fm), libaudit.NoWait); err != nil {
                        return errors.Wrap(err, "failed to set audit failure mode in kernel")
                }
        }

        if status.BacklogLimit != as.config.BacklogLimit {
                if err = as.client.SetBacklogLimit(as.config.BacklogLimit, libaudit.NoWait); err != nil {
                        return errors.Wrap(err, "failed to set audit backlog limit in kernel")
                }
        }

        if as.backpressureStrategy&(bsKernel|bsAuto) != 0 {
                // "kernel" backpressure mitigation strategy
                //
                // configure the kernel to drop audit events immediately if the
                // backlog queue is full.
                if status.FeatureBitmap&libaudit.AuditFeatureBitmapBacklogWaitTime != 0 {
                        glog.Info("Setting kernel backlog wait time to prevent backpressure propagating to the kernel.")
                        if err = as.client.SetBacklogWaitTime(0, libaudit.NoWait); err != nil {
                                return errors.Wrap(err, "failed to set audit backlog wait time in kernel")
                        }
                } else {
                        if as.backpressureStrategy == bsAuto {
                                glog.Warning("setting backlog wait time is not supported in this kernel. Enabling workaround.")
                                as.backpressureStrategy |= bsUserSpace
                        } else {
                                return errors.New("kernel backlog wait time not supported by kernel, but required by backpressure_strategy")
                        }
                }
        }

        if as.backpressureStrategy&(bsKernel|bsUserSpace) == bsUserSpace && as.config.RateLimit == 0 {
                // force a rate limit if the user-space strategy will be used without
                // corresponding backlog_wait_time setting in the kernel
                as.config.RateLimit = 5000
        }

        if status.RateLimit != as.config.RateLimit {
                if err = as.client.SetRateLimit(as.config.RateLimit, libaudit.NoWait); err != nil {
                        return errors.Wrap(err, "failed to set audit rate limit in kernel")
                }
        }

        if status.Enabled == 0 {
                if err = as.client.SetEnabled(true, libaudit.NoWait); err != nil {
                        return errors.Wrap(err, "failed to enable auditing in the kernel")
                }
        }
        if err := as.client.WaitForPendingACKs(); err != nil {
                return errors.Wrap(err, "failed to wait for ACKs")
        }
        if err := as.client.SetPID(libaudit.WaitForReply); err != nil {
                if errno, ok := err.(syscall.Errno); ok && errno == syscall.EEXIST && status.PID != 0 {
                        return fmt.Errorf("failed to set audit PID. An audit process is already running (PID %d)", status.PID)
                }
                return errors.Wrapf(err, "failed to set audit PID (current audit PID %d)", status.PID)
        }
        return nil
}

func newAuditClient(c *Config) (*libaudit.AuditClient, error) {
        var err error
        c.SocketType, err = determineSocketType(c)
        if err != nil {
                return nil, err
        }
        glog.Infof("socket_type=%s will be used.", c.SocketType)

        if c.SocketType == multicast {
                return libaudit.NewMulticastAuditClient(nil)
        }
        return libaudit.NewAuditClient(nil)
}

func kernelVersion() (major, minor int, full string, err error) {
        var uname syscall.Utsname
        if err := syscall.Uname(&uname); err != nil {
                return 0, 0, "", err
        }

        length := len(uname.Release)
        data := make([]byte, length)
        for i, v := range uname.Release {
                if v == 0 {
                        length = i
                        break
                }
                data[i] = byte(v)
        }

        release := string(data[:length])
        parts := strings.SplitN(release, ".", 3)
        if len(parts) < 2 {
                return 0, 0, release, errors.Errorf("failed to parse uname release '%v'", release)
        }

        major, err = strconv.Atoi(parts[0])
        if err != nil {
                return 0, 0, release, errors.Wrapf(err, "failed to parse major version from '%v'", release)
        }

        minor, err = strconv.Atoi(parts[1])
        if err != nil {
                return 0, 0, release, errors.Wrapf(err, "failed to parse minor version from '%v'", release)
        }

        return major, minor, release, nil
}

func determineSocketType(c *Config) (string, error) {
        client, err := libaudit.NewAuditClient(nil)
        if err != nil {
                if c.SocketType == "" {
                        return "", errors.Wrap(err, "failed to create audit client")
                }
                // Ignore errors if a socket type has been specified. It will fail during
                // further setup and its necessary for unit tests to pass
                return c.SocketType, nil
        }
        defer client.Close()
        status, err := client.GetStatus()
        if err != nil {
                if c.SocketType == "" {
                        return "", errors.Wrap(err, "failed to get audit status")
                }
                return c.SocketType, nil
        }
        rules := c.rules()

        isLocked := status.Enabled == auditLocked
        hasMulticast := hasMulticastSupport()
        hasRules := len(rules) > 0

        const useAutodetect = "Remove the socket_type option to have auditbeat " +
                "select the most suitable subscription method."
        switch c.SocketType {
        case unicast:
                if isLocked {
                        glog.Errorf("requested unicast socket_type is not available "+
                                "because audit configuration is locked in the kernel "+
                                "(enabled=2). %s", useAutodetect)
                        return "", errors.New("unicast socket_type not available")
                }
                return c.SocketType, nil

        case multicast:
                if hasMulticast {
                        if hasRules {
                                glog.Warning("The audit rules specified in the configuration " +
                                        "cannot be applied when using a multicast socket_type.")
                        }
                        return c.SocketType, nil
                }
                glog.Errorf("socket_type is set to multicast but based on the "+
                        "kernel version, multicast audit subscriptions are not supported. %s",
                        useAutodetect)
                return "", errors.New("multicast socket_type not available")

        default:
                // attempt to determine the optimal socket_type
                if hasMulticast {
                        if hasRules {
                                if isLocked {
                                        glog.Warning("Audit rules specified in the configuration " +
                                                "cannot be applied because the audit rules have been locked " +
                                                "in the kernel (enabled=2). A multicast audit subscription " +
                                                "will be used instead, which does not support setting rules")
                                        return multicast, nil
                                }
                                return unicast, nil
                        }
                        return multicast, nil
                }
                if isLocked {
                        glog.Errorf("Cannot continue: audit configuration is locked " +
                                "in the kernel (enabled=2) which prevents using unicast " +
                                "sockets. Multicast audit subscriptions are not available " +
                                "in this kernel. Disable locking the audit configuration " +
                                "to use auditbeat.")
                        return "", errors.New("no connection to audit available")
                }
                return unicast, nil
        }

}

func updateKernelLostMetric(as *AuditSet, lost uint32) {
        if !as.kernelLost.enabled {
                return
        }
        delta := int64(lost - as.kernelLost.counter)
        if delta >= 0 {
                glog.Warningf("kernel lost events: %d (total: %d)", delta, lost)
        } else {
                glog.Warningf("kernel lost event counter reset from %d to %d", as.kernelLost, lost)
        }
        as.kernelLost.counter = lost
}

func getBackpressureStrategy(value string) backpressureStrategy {
        switch value {
        case "kernel":
                return bsKernel
        case "userspace", "user-space":
                return bsUserSpace
        case "auto":
                return bsAuto
        case "both":
                return bsKernel | bsUserSpace
        case "none":
                return 0
        default:
                glog.Warning("Unknown value for the 'backpressure_strategy' option. Using default.")
                fallthrough
        case "", "default":
                return bsAuto
        }
}

func hasMulticastSupport() bool {
        // Check the kernel version because 3.16+ should have multicast
        // support.
        major, minor, _, err := kernelVersion()
        if err != nil {
                // Assume not supported.
                return false
        }

        switch {
        case major > 3,
                major == 3 && minor >= 16:
                return true
        }

        return false
}

