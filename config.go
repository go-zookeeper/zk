package zk

type SASLConfig struct {
	SASLType  SASLType
	KRBConfig *KRBConfig
}

type KRBConfig struct {
	KeytabPath  string
	KrbCfgPath  string
	Username    string
	Password    string
	Realm       string
	ServiceName string
	PAFXFAST    bool
}
