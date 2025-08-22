package main

import configpkg "github.com/akadatalimited/breathgslb/config"

type (
	Config           = configpkg.Config
	Zone             = configpkg.Zone
	HealthConfig     = configpkg.HealthConfig
	IPAddr           = configpkg.IPAddr
	GeoIPConfig      = configpkg.GeoIPConfig
	GeoTierPolicy    = configpkg.GeoTierPolicy
	GeoPolicy        = configpkg.GeoPolicy
	GeoAnswerSet     = configpkg.GeoAnswerSet
	GeoAnswers       = configpkg.GeoAnswers
	DNSSECZoneConfig = configpkg.DNSSECZoneConfig
	TSIGGlobalConfig = configpkg.TSIGGlobalConfig
	TSIGKey          = configpkg.TSIGKey
	TSIGZoneConfig   = configpkg.TSIGZoneConfig
	TXTRecord        = configpkg.TXTRecord
	MXRecord         = configpkg.MXRecord
	CAARecord        = configpkg.CAARecord
	RPRecord         = configpkg.RPRecord
	SSHFPRecord      = configpkg.SSHFPRecord
	SRVRecord        = configpkg.SRVRecord
	NAPTRRecord      = configpkg.NAPTRRecord
)
