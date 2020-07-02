package flw

const DefaultPort = 2181

// Mode is used to build custom server modes (leader|follower|standalone).
type Mode uint8

func (m Mode) String() string {
	if name := modeNames[m]; name != "" {
		return name
	}
	return "unknown"
}

const (
	ModeUnknown    Mode = iota
	ModeLeader     Mode = iota
	ModeFollower   Mode = iota
	ModeStandalone Mode = iota
)

var (
	modeNames = map[Mode]string{
		ModeLeader:     "leader",
		ModeFollower:   "follower",
		ModeStandalone: "standalone",
	}
)
