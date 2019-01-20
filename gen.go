package packet

type P2PHello struct {
	IntradomainRoutingProcotolID uint8
	PDULength uint16
	TLVs []*TLV
}

func (x *P2PHello) Serialize(buf *bytes.Buffer) {
	buf.WriteByte(x.IntradomainRoutingProcotolID)
	x.PDULength.Serialize(buf)
	for i := range TLVs {
		TLVs[i].Serialize(buf)
	}
}

func DeserializeP2PHello(buf *bytes.Buffer) (*P2PHello, int, error) {
	pdu := &P2PHello{}

	var readBytes int
	var err error
	var fields []interface{}

	fields = []interface{}{
		&pdu.IntradomainRoutingProcotolID,
		&pdu.PDULength,
	}

	err = decode.Decode(buf, fields)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode fields: %v", err)
	}
	readBytes += 3

	for i := 0; i < pdu.PDULength; {
		tlv, n, err := DeserializeTLVs(buf)
		if err != nil {
			return nil, 0, errors.Wrap(err, "Unable to decode")
		}
		pdu.TLVs := append(pdu.TLVs, tlv)
		i += n
		readBytes += n
	}

	return pdu, readBytes, nil
}
type AreaAddressesTLV struct {
	Type uint8
	Length uint8
	LANAddresses []*LANAddress
}

func (x *AreaAddressesTLV) Serialize(buf *bytes.Buffer) {
	buf.WriteByte(x.Type)
	buf.WriteByte(x.Length)
	for i := range LANAddresses {
		LANAddresses[i].Serialize(buf)
	}
}

func DeserializeAreaAddressesTLV(buf *bytes.Buffer) (*AreaAddressesTLV, int, error) {
	pdu := &AreaAddressesTLV{}

	var readBytes int
	var err error
	var fields []interface{}

	fields = []interface{}{
		&pdu.Type,
		&pdu.Length,
	}

	err = decode.Decode(buf, fields)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode fields: %v", err)
	}
	readBytes += 2

	for i := 0; i < pdu.Length; {
		tlv, n, err := DeserializeLANAddresses(buf)
		if err != nil {
			return nil, 0, errors.Wrap(err, "Unable to decode")
		}
		pdu.LANAddresses := append(pdu.LANAddresses, tlv)
		i += n
		readBytes += n
	}

	return pdu, readBytes, nil
}
type LANAddress struct {
	LANAddress [6]byte
}

func (x *LANAddress) Serialize(buf *bytes.Buffer) {
	x.LANAddress.Serialize(buf)
}

func DeserializeLANAddress(buf *bytes.Buffer) (*LANAddress, int, error) {
	pdu := &LANAddress{}

	var readBytes int
	var err error
	var fields []interface{}

	fields = []interface{}{
		&pdu.LANAddress,
	}

	err = decode.Decode(buf, fields)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode fields: %v", err)
	}
	readBytes += 6

	return pdu, readBytes, nil
}
type ISSystemNeighborsTLV struct {
	Type uint8
	Length uint8
	AreaAddressContainers []*AreaAddressContainer
}

func (x *ISSystemNeighborsTLV) Serialize(buf *bytes.Buffer) {
	buf.WriteByte(x.Type)
	buf.WriteByte(x.Length)
	for i := range AreaAddressContainers {
		AreaAddressContainers[i].Serialize(buf)
	}
}

func DeserializeISSystemNeighborsTLV(buf *bytes.Buffer) (*ISSystemNeighborsTLV, int, error) {
	pdu := &ISSystemNeighborsTLV{}

	var readBytes int
	var err error
	var fields []interface{}

	fields = []interface{}{
		&pdu.Type,
		&pdu.Length,
	}

	err = decode.Decode(buf, fields)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode fields: %v", err)
	}
	readBytes += 2

	for i := 0; i < pdu.; {
		tlv, n, err := DeserializeAreaAddressContainers(buf)
		if err != nil {
			return nil, 0, errors.Wrap(err, "Unable to decode")
		}
		pdu.AreaAddressContainers := append(pdu.AreaAddressContainers, tlv)
		i += n
		readBytes += n
	}

	return pdu, readBytes, nil
}
type AreaAddressContainer struct {
	AddressLength uint8
	AreaAddress []byte
}

func (x *AreaAddressContainer) Serialize(buf *bytes.Buffer) {
	buf.WriteByte(x.AddressLength)
	buf.Write(x.AreaAddress)
}

func DeserializeAreaAddressContainer(buf *bytes.Buffer) (*AreaAddressContainer, int, error) {
	pdu := &AreaAddressContainer{}

	var readBytes int
	var err error
	var fields []interface{}

	fields = []interface{}{
		&pdu.AddressLength,
		&pdu.AreaAddress,
	}

	err = decode.Decode(buf, fields)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode fields: %v", err)
	}
	readBytes += 1

	return pdu, readBytes, nil
}
type NLRI struct {
	Pfxlen uint8
	Address bnet.IP
}

func (x *NLRI) Serialize(buf *bytes.Buffer) {
	buf.WriteByte(x.Pfxlen)
	x.Address.Serialize(buf)
}

func DeserializeNLRI(buf *bytes.Buffer) (*NLRI, int, error) {
	pdu := &NLRI{}

	var readBytes int
	var err error
	var fields []interface{}

	fields = []interface{}{
		&pdu.Pfxlen,
		&pdu.Address,
	}

	err = decode.Decode(buf, fields)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode fields: %v", err)
	}
	readBytes += 1

	return pdu, readBytes, nil
}
