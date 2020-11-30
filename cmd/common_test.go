// Copyright © 2020 BoxBoat engineering@boxboat.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
