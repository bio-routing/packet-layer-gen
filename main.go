package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"gopkg.in/src-d/enry.v1/regex"

	"github.com/prometheus/common/log"
	"gopkg.in/yaml.v2"
)

type Packets struct {
	Package string              `yaml:"package"`
	Packets []*PacketDefinition `yaml:"packets"`
}

type PacketDefinition struct {
	Name   string         `yaml:"name"`
	Fields []*PacketField `yaml:"fields"`
}

type PacketField struct {
	Name     string            `yaml:"name"`
	Type     string            `yaml:"type"`
	Multiple bool              `yaml:"multiple"`
	Length   string            `yaml:"length"`
	Flags    []PacketFieldFlag `yaml:"flags"`
}

type PacketFieldFlag struct {
	Name   string `yaml:"name"`
	Offset uint8  `yaml:"offset"`
}

var (
	defFilePath = flag.String("def", "def.yml", "Definition file")
)

func main() {
	file, err := ioutil.ReadFile(*defFilePath)
	if err != nil {
		log.Errorf("Unable to read file: %v", err)
		os.Exit(1)
	}

	pdefs := &Packets{}
	err = yaml.Unmarshal(file, pdefs)
	if err != nil {
		log.Errorf("Unable to unmarshal: %v", err)
		os.Exit(1)
	}

	buf := bytes.NewBuffer(nil)
	fmt.Fprintf(buf, "package %s\n\n", pdefs.Package)
	for _, pdef := range pdefs.Packets {
		generatePacketLayerStruct(pdef, buf)
		generatePacketLayerStructSerializer(pdef, buf)
		generatePacketLayerStructDeserializer(pdef, buf)
	}

	fmt.Print(string(buf.Bytes()))
}

func generatePacketLayerStruct(pdef *PacketDefinition, b *bytes.Buffer) {
	fmt.Fprintf(b, "type %s struct {\n", pdef.Name)
	for _, f := range pdef.Fields {
		f.generateStruct(b)
	}
	fmt.Fprintf(b, "}\n\n")
}

func (pf *PacketField) generateStruct(b *bytes.Buffer) {
	if pf.Multiple {
		fmt.Fprintf(b, "\t%s []*%s\n", pf.Name, pf.Type)
		return
	}

	fmt.Fprintf(b, "\t%s %s\n", pf.Name, pf.Type)
}

func generatePacketLayerStructSerializer(pdef *PacketDefinition, b *bytes.Buffer) {
	fmt.Fprintf(b, "func (x *%s) Serialize(buf *bytes.Buffer) {\n", pdef.Name)
	for _, f := range pdef.Fields {
		f.generateStructSerialize(b)
	}
	fmt.Fprintf(b, "}\n\n")
}

func (pf *PacketField) generateStructSerialize(b *bytes.Buffer) {
	switch pf.Type {
	case "uint8":
		fmt.Fprintf(b, "\tbuf.WriteByte(x.%s)\n", pf.Name)
	case "uint16:":
		fmt.Fprintf(b, "\tbuf.Write(convert.Uint16Byte(x.%s))\n", pf.Name)
	case "uint32":
		fmt.Fprintf(b, "\tbuf.Write(convert.Uint32Byte(x.%s))\n", pf.Name)
	case "uint64":
		fmt.Fprintf(b, "\tbuf.Write(convert.Uint64Byte(x.%s))\n", pf.Name)
	case "[]byte":
		fmt.Fprintf(b, "\tbuf.Write(x.%s)\n", pf.Name)
	default:
		if pf.Multiple {
			fmt.Fprintf(b, "\tfor i := range x.%s {\n", pf.Name)
			fmt.Fprintf(b, "\t	x.%s[i].Serialize(buf)\n", pf.Name)
			fmt.Fprintf(b, "\t}\n")
			return
		}

		fmt.Fprintf(b, "\tx.%s.Serialize(buf)\n", pf.Name)
	}
}

func generatePacketLayerStructDeserializer(pdef *PacketDefinition, b *bytes.Buffer) {
	fmt.Fprintf(b, "func Deserialize%s(buf *bytes.Buffer) (*%s, int, error) {\n", pdef.Name, pdef.Name)
	fmt.Fprintf(b, "\tpdu := &%s{}\n\n", pdef.Name)
	fmt.Fprintf(b, "\tvar readBytes int\n")
	fmt.Fprintf(b, "\tvar err error\n")
	fmt.Fprintf(b, "\tvar fields []interface{}\n\n")

	lastMultiple := false
	begin := 0
	for i, f := range pdef.Fields {
		if f.Multiple {
			blockOfNonMultiple(pdef.Fields[begin:i], b)
			begin = i + 1
			multiple(f, b)
			lastMultiple = true
			continue
		}
		lastMultiple = false
	}

	if !lastMultiple {
		blockOfNonMultiple(pdef.Fields[begin:], b)
	}

	fmt.Fprintf(b, "\treturn pdu, readBytes, nil\n")
	fmt.Fprintf(b, "}\n")
}

func typeSize(t string) int {
	switch t {
	case "uint8":
		return 1
	case "uint16":
		return 2
	case "uint32":
		return 4
	case "uint64":
		return 8
	}

	match := regex.MustCompile(`^\[(\d+)\]`).FindStringSubmatch(t)
	if len(match) < 2 {
		return 0
	}

	n, err := strconv.Atoi(match[1])
	if err != nil {
		panic(err)
	}

	return n
}

func multiple(f *PacketField, b *bytes.Buffer) {
	fmt.Fprintf(b, "\tfor i := 0; i < pdu.%s; {\n", f.Length)
	fmt.Fprintf(b, "\t	tlv, n, err := Deserialize%s(buf)\n", f.Name)
	fmt.Fprintf(b, "\t	if err != nil {\n")
	fmt.Fprintf(b, "\t		return nil, 0, errors.Wrap(err, \"Unable to decode\")\n")
	fmt.Fprintf(b, "\t	}\n")
	fmt.Fprintf(b, "\t	pdu.%s := append(pdu.%s, tlv)\n", f.Name, f.Name)
	fmt.Fprintf(b, "\t	i += n\n")
	fmt.Fprintf(b, "\t	readBytes += n\n")
	fmt.Fprintf(b, "\t}\n\n")
}

func blockOfNonMultiple(fields []*PacketField, b *bytes.Buffer) {
	fmt.Fprintf(b, "\tfields = []interface{}{\n")
	n := 0
	for _, f := range fields {
		fmt.Fprintf(b, "\t\t&pdu.%s,\n", f.Name)
		n += typeSize(f.Type)

	}
	fmt.Fprintf(b, "\t}\n\n")
	fmt.Fprintf(b, "\terr = decode.Decode(buf, fields)\n")
	fmt.Fprintf(b, "\tif err != nil {\n")
	fmt.Fprint(b, "\t\treturn nil, fmt.Errorf(\"Unable to decode fields: %v\", err)\n")
	fmt.Fprintf(b, "\t}\n")
	fmt.Fprintf(b, "\treadBytes += %d\n\n", n)
}

func (pf *PacketField) generateStructDeserializer(b *bytes.Buffer) {
	if !pf.Multiple {

	}
}
