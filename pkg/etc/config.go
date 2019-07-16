package etc

import "os"

type Config struct {
	Addr             string
	RegistryURL      string
	RegistryUsername string
	RegistryPassword string
}

func GetConfig() (*Config, error) {
	cfg := &Config{
		Addr: ":8080",
	}
	if addr, ok := os.LookupEnv("ADAPTER_ADDR"); ok {
		cfg.Addr = addr
	}
	if registryURL, ok := os.LookupEnv("ADAPTER_REGISTRY_URL"); ok {
		cfg.RegistryURL = registryURL
	}
	if username, ok := os.LookupEnv("ADAPTER_REGISTRY_USERNAME"); ok {
		cfg.RegistryUsername = username
	}
	if pwd, ok := os.LookupEnv("ADAPTER_REGISTRY_PASSWORD"); ok {
		cfg.RegistryPassword = pwd
	}
	return cfg, nil
}
