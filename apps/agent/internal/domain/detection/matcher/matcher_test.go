package matcher

import "testing"

func TestMatchers(t *testing.T) {
	for _, strategy := range []Strategy{StrategyLinear, StrategyOptimized} {
		t.Run(string(strategy), func(t *testing.T) {
			SetDefaultStrategy(strategy)
			t.Cleanup(func() { SetDefaultStrategy(StrategyLinear) })
			tests := []struct {
				name    string
				matcher Matcher
				value   string
				want    bool
			}{
				{name: "exact hit", matcher: NewExact([]string{"443", "8443"}), value: "443", want: true},
				{name: "exact miss", matcher: NewExact([]string{"443", "8443"}), value: "80", want: false},
				{name: "prefix hit", matcher: NewPrefix([]string{"/tmp/", "/dev/shm/"}), value: "/tmp/payload", want: true},
				{name: "prefix miss", matcher: NewPrefix([]string{"/tmp/", "/dev/shm/"}), value: "/var/log/app", want: false},
				{name: "suffix hit", matcher: NewSuffix([]string{".sh", ".so"}), value: "/tmp/x.sh", want: true},
				{name: "suffix miss", matcher: NewSuffix([]string{".sh", ".so"}), value: "/tmp/x.py", want: false},
				{name: "contains hit", matcher: NewContains([]string{" curl ", " wget "}), value: "/bin/sh -c curl http://example.invalid", want: true},
				{name: "contains miss", matcher: NewContains([]string{" curl ", " wget "}), value: "/usr/bin/python app.py", want: false},
				{name: "contains hit by non-leading indexed byte", matcher: NewContains([]string{"abcxyz"}), value: "--abcxyz--", want: true},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					if got := tt.matcher.Match(tt.value); got != tt.want {
						t.Fatalf("Match() = %t, want %t", got, tt.want)
					}
				})
			}
		})
	}
}

func TestMatcherStrategiesAreEquivalent(t *testing.T) {
	cases := []struct {
		name   string
		build  func([]string) Matcher
		values []string
		inputs []string
	}{
		{
			name:  "prefix mixed lengths",
			build: NewPrefix,
			values: []string{
				"/tmp/",
				"/var/lib/app/plugins/helper",
				"/var/lib/app/plugins/helper-stage",
				"/dev/shm/",
				"/home/ci/workspace/",
			},
			inputs: []string{
				"/tmp/payload",
				"/var/lib/app/plugins/helper",
				"/var/lib/app/plugins/helper-stage/x",
				"/var/log/app",
				"",
			},
		},
		{
			name:  "suffix mixed lengths",
			build: NewSuffix,
			values: []string{
				".sh",
				".payload.so",
				".very.long.extension",
				".py",
			},
			inputs: []string{
				"/tmp/x.sh",
				"/tmp/x.payload.so",
				"/tmp/x.txt",
				"",
			},
		},
		{
			name:  "contains preserves spaces",
			build: NewContains,
			values: []string{
				" curl ",
				" wget ",
				"token-without-spaces",
				"--connect ",
			},
			inputs: []string{
				"/bin/sh -c curl http://example.invalid",
				"/usr/bin/scurl-helper",
				"/bin/sh -c token-without-spaces",
				"/bin/tool --connect 10.66.0.99:443",
				"",
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			SetDefaultStrategy(StrategyLinear)
			linear := tt.build(tt.values)
			SetDefaultStrategy(StrategyOptimized)
			optimized := tt.build(tt.values)
			t.Cleanup(func() { SetDefaultStrategy(StrategyLinear) })

			for _, input := range tt.inputs {
				want := linear.Match(input)
				if got := optimized.Match(input); got != want {
					t.Fatalf("optimized Match(%q) = %t, want linear %t", input, got, want)
				}
			}
		})
	}
}

func TestDefaultStrategyRejectsUnknown(t *testing.T) {
	SetDefaultStrategy(StrategyOptimized)
	t.Cleanup(func() { SetDefaultStrategy(StrategyLinear) })
	SetDefaultStrategy(Strategy("unknown"))
	if got := DefaultStrategy(); got != StrategyLinear {
		t.Fatalf("DefaultStrategy() = %q, want %q", got, StrategyLinear)
	}
}
