package relation

import (
	"testing"
)

func TestParseTuple(t *testing.T) {
	tests := []struct {
		input   string
		want    Tuple
		wantErr bool
	}{
		{
			input: "admin",
			want:  Tuple{Relation: "admin", ObjectType: "*", ObjectID: "*"},
		},
		{
			input: "service:zwei#admin",
			want:  Tuple{Relation: "admin", ObjectType: "service", ObjectID: "zwei"},
		},
		{
			input: "service:zwei#admin@user:alice",
			want:  Tuple{Relation: "admin", ObjectType: "service", ObjectID: "zwei", SubjectType: "user", SubjectID: "alice"},
		},
		{
			input: "*:*#viewer",
			want:  Tuple{Relation: "viewer", ObjectType: "*", ObjectID: "*"},
		},
		{
			input: "service:{path.service_id}#editor",
			want:  Tuple{Relation: "editor", ObjectType: "service", ObjectID: "{path.service_id}"},
		},
		{
			input: "zone:{path.zid}#control@device:{path.did}",
			want:  Tuple{Relation: "control", ObjectType: "zone", ObjectID: "{path.zid}", SubjectType: "device", SubjectID: "{path.did}"},
		},
		{
			input: "staff:admin",
			want:  Tuple{Relation: "staff:admin", ObjectType: "*", ObjectID: "*"},
		},
		{input: "", wantErr: true},
		{input: "#admin", wantErr: true},
		{input: "service:#admin", wantErr: true},
		{input: "service:zwei#admin@", wantErr: true},
		{input: "service:zwei#admin@badsubject", wantErr: true},
		{input: "service:zwei#", wantErr: true},
		{input: "service:zwei#admin || editor", wantErr: true},
	}

	for _, tt := range tests {
		got, err := ParseTuple(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseTuple(%q) expected error, got %+v", tt.input, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTuple(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if *got != tt.want {
			t.Errorf("ParseTuple(%q) = %+v, want %+v", tt.input, *got, tt.want)
		}
	}
}

func TestTuple_HasBinding(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"admin", false},
		{"service:zwei#admin", false},
		{"service:{path.id}#admin", true},
		{"service:zwei#admin@device:{path.did}", true},
	}

	for _, tt := range tests {
		tuple, err := ParseTuple(tt.input)
		if err != nil {
			t.Fatalf("ParseTuple(%q) error: %v", tt.input, err)
		}
		if got := tuple.HasBinding(); got != tt.want {
			t.Errorf("ParseTuple(%q).HasBinding() = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestParseEntity(t *testing.T) {
	tests := []struct {
		input   string
		wantTyp string
		wantID  string
		wantErr bool
	}{
		{"user:alice", "user", "alice", false},
		{"service:zwei", "service", "zwei", false},
		{"*:*", "*", "*", false},
		{"device:{path.did}", "device", "{path.did}", false},
		{"", "", "", true},
		{"nocolon", "", "", true},
		{":id", "", "", true},
		{"type:", "", "", true},
	}

	for _, tt := range tests {
		typ, id, err := ParseEntity(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseEntity(%q) expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseEntity(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if typ != tt.wantTyp || id != tt.wantID {
			t.Errorf("ParseEntity(%q) = (%q, %q), want (%q, %q)", tt.input, typ, id, tt.wantTyp, tt.wantID)
		}
	}
}
