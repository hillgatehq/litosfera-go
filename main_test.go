package main

import (
	"reflect"
	"testing"
)

func TestListenerConfigs(t *testing.T) {
	for _, tc := range []struct {
		name, env       string
		port            int
		envSet, portSet bool
		want            []listenerConfig
	}{
		{"default", "", 0, false, false, []listenerConfig{{"TEST", 9899}, {"PROD", 9898}}},
		{"test", "TEST", 0, true, false, []listenerConfig{{"TEST", 9899}}},
		{"prod", "PROD", 0, true, false, []listenerConfig{{"PROD", 9898}}},
		{"test override", "TEST", 9000, true, true, []listenerConfig{{"TEST", 9000}}},
		{"prod override", "PROD", 9001, true, true, []listenerConfig{{"PROD", 9001}}},
		{"port only", "", 9899, false, true, nil},
		{"empty environment", "", 0, true, false, nil},
		{"invalid environment", "OTHER", 0, true, false, nil},
		{"zero port", "TEST", 0, true, true, nil},
		{"negative port", "TEST", -1, true, true, nil},
		{"out of range port", "PROD", 65536, true, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := listenerConfigs(tc.env, tc.port, tc.envSet, tc.portSet)
			if tc.want == nil {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDefaultModulePath(t *testing.T) {
	for _, tc := range []struct{ os, root, want string }{
		{"windows", `C:\Windows`, `C:\Windows\System32\eTPKCS11.dll`},
		{"windows", `D:\Windows\`, `D:\Windows\System32\eTPKCS11.dll`},
		{"windows", "", `C:\Windows\System32\eTPKCS11.dll`},
		{"darwin", "", "/usr/local/lib/libeTPkcs11.dylib"},
	} {
		if got := defaultModulePath(tc.os, tc.root); got != tc.want {
			t.Errorf("defaultModulePath(%q,%q)=%q, want %q", tc.os, tc.root, got, tc.want)
		}
	}
}

func TestLinuxModulePath(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed []string
		want      string
	}{
		{"lib64", []string{"/usr/lib64/libeTPkcs11.so"}, "/usr/lib64/libeTPkcs11.so"},
		{"lib", []string{"/usr/lib/libeTPkcs11.so"}, "/usr/lib/libeTPkcs11.so"},
		{"both", []string{"/usr/lib64/libeTPkcs11.so", "/usr/lib/libeTPkcs11.so"}, "/usr/lib64/libeTPkcs11.so"},
		{"missing", nil, "/usr/lib/libeTPkcs11.so"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := linuxModulePath(func(path string) bool {
				for _, p := range tc.installed {
					if path == p {
						return true
					}
				}
				return false
			})
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
