package main

import configpkg "github.com/akadatalimited/breathgslb/src/config"

type (
	Config           = configpkg.Config
	Zone             = configpkg.Zone
	HealthConfig     = configpkg.HealthConfig
	IPAddr           = configpkg.IPAddr
	GeoIPConfig      = configpkg.GeoIPConfig
	GeoTierPolicy    = configpkg.GeoTierPolicy
	NamedGeoPolicy   = configpkg.NamedGeoPolicy
	GeoPolicy        = configpkg.GeoPolicy
	GeoAnswerSet     = configpkg.GeoAnswerSet
	GeoAnswers       = configpkg.GeoAnswers
	Host             = configpkg.Host
	Pool             = configpkg.Pool
	LightupFamily    = configpkg.LightupFamily
	LightupConfig    = configpkg.LightupConfig
	DNSSECMode       = configpkg.DNSSECMode
	DNSSECZoneConfig = configpkg.DNSSECZoneConfig
	TSIGGlobalConfig = configpkg.TSIGGlobalConfig
	TSIGKey          = configpkg.TSIGKey
	TSIGZoneConfig   = configpkg.TSIGZoneConfig
	DiscoveryConfig  = configpkg.DiscoveryConfig
	TXTRecord        = configpkg.TXTRecord
	MXRecord         = configpkg.MXRecord
	CAARecord        = configpkg.CAARecord
	RPRecord         = configpkg.RPRecord
	SSHFPRecord      = configpkg.SSHFPRecord
	SRVRecord        = configpkg.SRVRecord
	NAPTRRecord      = configpkg.NAPTRRecord
	PTRRecord        = configpkg.PTRRecord
)

const (
	DNSSECModeOff       = configpkg.DNSSECModeOff
	DNSSECModeManual    = configpkg.DNSSECModeManual
	DNSSECModeGenerated = configpkg.DNSSECModeGenerated
)
