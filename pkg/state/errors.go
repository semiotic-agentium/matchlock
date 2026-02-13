package state

import "errors"

var (
	ErrNoAvailableSubnets   = errors.New("no available subnets")
	ErrSaveSubnetAllocation = errors.New("failed to save subnet allocation")
	ErrSubnetLockOpen       = errors.New("open subnet lock file")
	ErrSubnetLockAcquire    = errors.New("acquire subnet lock")
	ErrSubnetLockRelease    = errors.New("release subnet lock")
)
