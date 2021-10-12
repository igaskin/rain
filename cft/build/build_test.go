package build_test

import (
	"testing"

	"github.com/aws-cloudformation/rain/cft/build"
	"github.com/aws-cloudformation/rain/cft/spec"
)

var allResourceTypes = make(map[string]string)

func init() {
	for resourceType := range spec.ResourceTypes {
		allResourceTypes[resourceType] = resourceType
	}
}

func TestAllResourceTypes(t *testing.T) {
	for resourceType := range allResourceTypes {
		build.Template(map[string]string{
			"Res": resourceType,
		}, true)
	}
}

func BenchmarkAllResourceTypesIndividually(b *testing.B) {
	for n := 0; n < b.N; n++ {
		for resourceType := range allResourceTypes {
			build.Template(map[string]string{
				"Res": resourceType,
			}, true)
		}
	}
}

func BenchmarkAllResourceTypesInOne(b *testing.B) {
	for n := 0; n < b.N; n++ {
		build.Template(allResourceTypes, true)
	}
}
