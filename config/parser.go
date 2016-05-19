package config

import (
	"encoding/xml"
	"fmt"
	"os"
)

func Load(fileName string) (*Root, error) {
	// open xml
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	// parse xml
	root := new(Root)
	parser := xml.NewDecoder(file)
	err = parser.Decode(root)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %v: %v", fileName, err)
	}

	return root, nil
}
