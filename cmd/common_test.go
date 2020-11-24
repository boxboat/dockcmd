package cmd

import (
	"reflect"
	"testing"
)

func TestMergeMaps(t *testing.T) {

	tt := []struct {
		value1   map[string]interface{}
		value2   map[string]interface{}
		expected map[string]interface{}
	}{
		{map[string]interface{}{"key1": "value1", "key2": "value2"},
			map[string]interface{}{"key3": "value3", "key4": "value4"},
			map[string]interface{}{"key1": "value1", "key2": "value2", "key3": "value3", "key4": "value4"}},
		{map[string]interface{}{"key1": 1, "key2": 2},
			map[string]interface{}{"key3": 3, "key4": 4},
			map[string]interface{}{"key1": 1, "key2": 2, "key3": 3, "key4": 4}},
		{map[string]interface{}{"key1": "value1", "key2": []string{"one", "two"}},
			map[string]interface{}{"key3": 3, "key4": []byte("testing")},
			map[string]interface{}{"key1": "value1", "key2": []string{"one", "two"}, "key3": 3, "key4": []byte("testing")}},
	}

	for _, v := range tt {
		actual := mergeMaps(v.value1, v.value2)
		if !reflect.DeepEqual(actual, v.expected) {
			t.Errorf("Expected %s, got %s", v.expected, actual)
		}
	}

}
