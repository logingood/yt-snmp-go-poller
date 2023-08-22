package models

type OSDefinition struct {
	OS      string   `yaml:"os"`
	Group   string   `yaml:"group"`
	NoBulk  int      `yaml:"nobulk"`
	MibDir  []string `yaml:"mib_dir"`
	Text    string   `yaml:"text"`
	Type    string   `yaml:"type"`
	IfXmcbc int64    `yaml:"ifXmcbc"`
	Over    []struct {
		Graph string `yaml:"graph"`
		Text  string `yaml:"text"`
	} `yaml:"over"`
	Icon               string   `yaml:"icon"`
	Goodif             []string `yaml:"good_if"`
	IfName             int      `"yaml:ifname"`
	Processors_Stacked int      `yaml:"processor_stacked"`
	Discovery          []struct {
		SysDescr        []string `yaml:"sysDescr"`
		SysDescr_except []string `yaml:"sysDescr_except"`
		SysObjectId     []string `yaml:"sysObjectId"`
	} `yaml:"discovery"`
	Bad_ifXEntry      []string               `yaml:"bad_ifXEntry"`
	Poller_Modules    map[string]interface{} `yaml:"poller_modules"`
	Discovery_Modules map[string]interface{} `yaml:"discovery_modules"`
	Register_mibs     map[string]interface{} `yaml:"register_mibs"`
}
