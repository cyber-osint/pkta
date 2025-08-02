class PcapAnalyzer {
    constructor() {
        this.packets = [];
        this.filteredPackets = [];
        this.currentFile = null;
        this.currentPage = 1;
        this.pageSize = 100;
        this.totalPages = 1;
        this.selectedPacketRow = null;
        this.currentDetailsRow = null;
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const searchBtn = document.getElementById('searchBtn');
        const clearBtn = document.getElementById('clearBtn');
        const helpBtn = document.getElementById('helpBtn');
        const exportBtn = document.getElementById('exportBtn');
        const searchBox = document.getElementById('searchBox');

        // 페이징 관련 요소들
        const pageSize = document.getElementById('pageSize');
        const firstPageBtn = document.getElementById('firstPageBtn');
        const prevPageBtn = document.getElementById('prevPageBtn');
        const nextPageBtn = document.getElementById('nextPageBtn');
        const lastPageBtn = document.getElementById('lastPageBtn');
        const gotoBtn = document.getElementById('gotoBtn');
        const gotoPage = document.getElementById('gotoPage');

        uploadArea.addEventListener('click', () => fileInput.click());
        uploadArea.addEventListener('dragover', this.handleDragOver.bind(this));
        uploadArea.addEventListener('dragleave', this.handleDragLeave.bind(this));
        uploadArea.addEventListener('drop', this.handleDrop.bind(this));
        
        fileInput.addEventListener('change', this.handleFileSelect.bind(this));
        searchBtn.addEventListener('click', this.handleSearch.bind(this));
        clearBtn.addEventListener('click', this.handleClear.bind(this));
        helpBtn.addEventListener('click', this.toggleSearchHelp.bind(this));
        exportBtn.addEventListener('click', this.handleExport.bind(this));
        
        searchBox.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.handleSearch();
        });

        // 페이징 이벤트 리스너
        pageSize.addEventListener('change', this.handlePageSizeChange.bind(this));
        firstPageBtn.addEventListener('click', () => this.goToPage(1));
        prevPageBtn.addEventListener('click', () => this.goToPage(this.currentPage - 1));
        nextPageBtn.addEventListener('click', () => this.goToPage(this.currentPage + 1));
        lastPageBtn.addEventListener('click', () => this.goToPage(this.totalPages));
        gotoBtn.addEventListener('click', this.handleGotoPage.bind(this));
        gotoPage.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.handleGotoPage();
        });
    }

    handleDragOver(e) {
        e.preventDefault();
        e.stopPropagation();
        e.currentTarget.classList.add('dragover');
    }

    handleDragLeave(e) {
        e.preventDefault();
        e.stopPropagation();
        e.currentTarget.classList.remove('dragover');
    }

    handleDrop(e) {
        e.preventDefault();
        e.stopPropagation();
        e.currentTarget.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files && files.length > 0) {
            console.log('File dropped:', files[0].name);
            this.processFile(files[0]);
        }
    }

    handleFileSelect(e) {
        const file = e.target.files[0];
        if (file) {
            this.processFile(file);
        }
    }

    async processFile(file) {
        this.currentFile = file;
        this.showLoading(true);
        this.hideError();

        try {
            console.log('Processing file:', file.name, 'Size:', file.size);
            const arrayBuffer = await this.readFileAsArrayBuffer(file);
            const uint8Array = new Uint8Array(arrayBuffer);
            
            console.log('File loaded, first 16 bytes:', Array.from(uint8Array.slice(0, 16)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' '));
            
            const packets = await this.parsePcapFile(uint8Array);
            console.log('Parsed packets count:', packets.length);
            
            this.packets = packets;
            this.filteredPackets = packets;
            
            if (packets.length === 0) {
                this.showError('파일에서 패킷을 찾을 수 없습니다. 파일이 손상되었거나 지원되지 않는 형식일 수 있습니다.');
                return;
            }
            
            this.displayFileInfo(file);
            this.displayStats();
            this.displayPackets();
            this.showAnalysisSection();
            
        } catch (error) {
            console.error('File processing error:', error);
            this.showError('파일 처리 중 오류가 발생했습니다: ' + error.message);
        } finally {
            this.showLoading(false);
        }
    }

    readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = e => resolve(e.target.result);
            reader.onerror = e => reject(new Error('파일을 읽을 수 없습니다.'));
            reader.readAsArrayBuffer(file);
        });
    }

    async parsePcapFile(data) {
        if (data.length < 24) {
            throw new Error('파일이 너무 작습니다. 유효한 PCAP 파일이 아닙니다.');
        }

        // 특수 CAP 파일 형식 확인 (예: Wireshark의 특별한 CAP 형식)
        const firstBytes = Array.from(data.slice(0, 8));
        if (firstBytes[0] === 0x54 && firstBytes[1] === 0x52) {
            console.log('Detected special CAP file format, attempting alternative parsing...');
            return this.parseSpecialCapFile(data);
        }

        // 매직 넘버를 빅엔디안과 리틀엔디안 둘 다 확인
        const magicBig = this.readUint32(data, 0, false);
        const magicLittle = this.readUint32(data, 0, true);
        let isLittleEndian = false;
        
        console.log('Magic numbers:', {
            bigEndian: '0x' + magicBig.toString(16).toUpperCase(),
            littleEndian: '0x' + magicLittle.toString(16).toUpperCase(),
            bytes: Array.from(data.slice(0, 4)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' ')
        });
        
        if (magicBig === 0xA1B2C3D4) {
            isLittleEndian = false;
            console.log('Detected: Big-endian PCAP');
        } else if (magicLittle === 0xA1B2C3D4 || magicBig === 0xD4C3B2A1) {
            isLittleEndian = true;
            console.log('Detected: Little-endian PCAP');
        } else if (magicBig === 0x0A0D0D0A || magicLittle === 0x0A0D0D0A) {
            console.log('Detected PCAP-NG file format');
            return this.parsePcapNgFile(data);
        } else {
            // 나노초 정밀도 PCAP 파일도 확인
            if (magicBig === 0xA1B23C4D || magicLittle === 0xA1B23C4D) {
                isLittleEndian = magicLittle === 0xA1B23C4D;
                console.log('Detected: Nanosecond precision PCAP');
            } else if (magicBig === 0x4D3CB2A1 || magicLittle === 0x4D3CB2A1) {
                isLittleEndian = magicBig === 0x4D3CB2A1;
                console.log('Detected: Nanosecond precision PCAP (alternative)');
            } else if (magicBig === 0x34CDB2A1 || magicLittle === 0x34CDB2A1) {
                isLittleEndian = magicBig === 0x34CDB2A1;
                console.log('Detected: FRITZ!Box PCAP variant');
            } else if (magicBig === 0x1C0001AC || magicLittle === 0x1C0001AC) {
                isLittleEndian = magicBig === 0x1C0001AC;
                console.log('Detected: IXIA LCAP format (hardware)');
            } else if (magicBig === 0x1C0001AB || magicLittle === 0x1C0001AB) {
                isLittleEndian = magicBig === 0x1C0001AB;
                console.log('Detected: IXIA LCAP format (software)');
            } else {
                // 알려지지 않은 형식 - 일반적인 바이너리 파일인지 확인해보기
                const firstInt = this.readUint32(data, 0, false);
                const secondInt = this.readUint32(data, 4, false);
                
                // 파일이 너무 작거나 명확히 PCAP가 아닌 경우
                if (data.length < 24) {
                    throw new Error('파일이 너무 작습니다. 유효한 PCAP 파일이 아닙니다.');
                }
                
                // 임시로 표준 PCAP로 가정하고 파싱 시도
                console.warn('Unknown magic number, attempting to parse as standard PCAP...');
                console.log(`First 4 bytes as magic: 0x${firstInt.toString(16)}`);
                console.log(`Second 4 bytes as length: ${secondInt}`);
                
                // 두 번째 값이 합리적인 길이(24-65535)인지 확인
                if (secondInt >= 24 && secondInt <= 65535) {
                    console.log('File might be a valid PCAP with unknown magic, proceeding...');
                    // 빅엔디안으로 가정하고 진행
                    isLittleEndian = false;
                } else {
                    // 리틀엔디안으로 다시 시도
                    const secondIntLE = this.readUint32(data, 4, true);
                    if (secondIntLE >= 24 && secondIntLE <= 65535) {
                        console.log('File might be a valid PCAP with unknown magic (little endian), proceeding...');
                        isLittleEndian = true;
                    } else {
                        const firstBytes = Array.from(data.slice(0, 16)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' ');
                        throw new Error(`지원되지 않는 파일 형식입니다.\n파일 시작 바이트: ${firstBytes}\n\n지원하는 PCAP 매직 넘버:\n- 0xA1B2C3D4 (표준 마이크로초)\n- 0xD4C3B2A1 (표준 마이크로초, 리틀엔디안)\n- 0xA1B23C4D (나노초)\n- 0x4D3CB2A1 (나노초, 리틀엔디안)\n- 0x34CDB2A1 (FRITZ!Box)\n- 0x1C0001AC (IXIA 하드웨어)\n- 0x1C0001AB (IXIA 소프트웨어)\n- 0x0A0D0D0A (PCAP-NG)`);
                    }
                }
            }
        }

        const header = this.parsePcapHeader(data, isLittleEndian);
        const packets = [];
        let offset = 24;

        while (offset < data.length) {
            try {
                const packet = this.parsePacketRecord(data, offset, isLittleEndian, header.network);
                if (packet) {
                    packets.push(packet);
                    offset = packet.nextOffset;
                } else {
                    break;
                }
            } catch (error) {
                console.warn('패킷 파싱 오류:', error);
                break;
            }
        }

        return packets;
    }

    parsePcapHeader(data, isLittleEndian) {
        return {
            magic: this.readUint32(data, 0, isLittleEndian),
            versionMajor: this.readUint16(data, 4, isLittleEndian),
            versionMinor: this.readUint16(data, 6, isLittleEndian),
            timezone: this.readInt32(data, 8, isLittleEndian),
            timestamp: this.readUint32(data, 12, isLittleEndian),
            maxPacketLength: this.readUint32(data, 16, isLittleEndian),
            network: this.readUint32(data, 20, isLittleEndian)
        };
    }

    parsePacketRecord(data, offset, isLittleEndian, networkType) {
        if (offset + 16 > data.length) {
            return null;
        }

        const timestamp = {
            seconds: this.readUint32(data, offset, isLittleEndian),
            microseconds: this.readUint32(data, offset + 4, isLittleEndian)
        };
        
        const capturedLength = this.readUint32(data, offset + 8, isLittleEndian);
        const originalLength = this.readUint32(data, offset + 12, isLittleEndian);
        
        if (offset + 16 + capturedLength > data.length) {
            return null;
        }

        const packetData = data.slice(offset + 16, offset + 16 + capturedLength);
        const parsed = this.parseEthernetFrame(packetData);

        return {
            timestamp: new Date((timestamp.seconds * 1000) + (timestamp.microseconds / 1000)),
            capturedLength,
            originalLength,
            data: packetData,
            parsed,
            nextOffset: offset + 16 + capturedLength
        };
    }

    parseEthernetFrame(data) {
        if (data.length < 14) {
            return { type: 'Invalid', info: 'Too short for Ethernet frame' };
        }

        const destMac = this.formatMacAddress(data.slice(0, 6));
        const srcMac = this.formatMacAddress(data.slice(6, 12));
        const etherType = this.readUint16(data, 12, false);

        let payload = data.slice(14);
        let protocol = 'Unknown';
        let info = '';
        let srcIP = '';
        let destIP = '';

        if (etherType === 0x0800) {
            const ipv4 = this.parseIPv4(payload);
            protocol = ipv4.protocol;
            srcIP = ipv4.srcIP;
            destIP = ipv4.destIP;
            info = ipv4.info;
        } else if (etherType === 0x86DD) {
            const ipv6 = this.parseIPv6(payload);
            protocol = 'IPv6';
            srcIP = ipv6.srcIP;
            destIP = ipv6.destIP;
            info = ipv6.info;
        } else if (etherType === 0x0806) {
            protocol = 'ARP';
            const arp = this.parseARP(payload);
            info = arp.info;
        }

        return {
            srcMac,
            destMac,
            etherType,
            protocol,
            srcIP,
            destIP,
            info,
            size: data.length
        };
    }

    parseIPv4(data) {
        if (data.length < 20) {
            return { protocol: 'IPv4', srcIP: '', destIP: '', info: 'Invalid IPv4 header' };
        }

        const version = (data[0] >> 4) & 0x0F;
        const headerLength = (data[0] & 0x0F) * 4;
        const protocol = data[9];
        const srcIP = this.formatIPv4Address(data.slice(12, 16));
        const destIP = this.formatIPv4Address(data.slice(16, 20));

        let protocolName = 'IPv4';
        let info = '';

        switch (protocol) {
            case 1:
                protocolName = 'ICMP';
                info = this.parseICMP(data.slice(headerLength));
                break;
            case 6:
                protocolName = 'TCP';
                info = this.parseTCP(data.slice(headerLength));
                break;
            case 17:
                protocolName = 'UDP';
                info = this.parseUDP(data.slice(headerLength));
                break;
            default:
                protocolName = `IPv4 (Protocol ${protocol})`;
        }

        return { protocol: protocolName, srcIP, destIP, info };
    }

    parseIPv6(data) {
        if (data.length < 40) {
            return { srcIP: '', destIP: '', info: 'Invalid IPv6 header' };
        }

        const srcIP = this.formatIPv6Address(data.slice(8, 24));
        const destIP = this.formatIPv6Address(data.slice(24, 40));
        const nextHeader = data[6];

        let info = `IPv6 Next Header: ${nextHeader}`;

        return { srcIP, destIP, info };
    }

    parseARP(data) {
        if (data.length < 28) {
            return { info: 'Invalid ARP packet' };
        }

        const operation = this.readUint16(data, 6, false);
        const senderIP = this.formatIPv4Address(data.slice(14, 18));
        const targetIP = this.formatIPv4Address(data.slice(24, 28));

        const opType = operation === 1 ? 'Request' : operation === 2 ? 'Reply' : 'Unknown';
        return { info: `ARP ${opType}: ${senderIP} -> ${targetIP}` };
    }

    parseTCP(data) {
        if (data.length < 20) {
            return 'Invalid TCP header';
        }

        const srcPort = this.readUint16(data, 0, false);
        const destPort = this.readUint16(data, 2, false);
        const flags = data[13];

        const flagNames = [];
        if (flags & 0x01) flagNames.push('FIN');
        if (flags & 0x02) flagNames.push('SYN');
        if (flags & 0x04) flagNames.push('RST');
        if (flags & 0x08) flagNames.push('PSH');
        if (flags & 0x10) flagNames.push('ACK');
        if (flags & 0x20) flagNames.push('URG');

        return `TCP ${srcPort} → ${destPort} [${flagNames.join(', ')}]`;
    }

    parseUDP(data) {
        if (data.length < 8) {
            return 'Invalid UDP header';
        }

        const srcPort = this.readUint16(data, 0, false);
        const destPort = this.readUint16(data, 2, false);
        const length = this.readUint16(data, 4, false);

        return `UDP ${srcPort} → ${destPort} Len=${length}`;
    }

    parseICMP(data) {
        if (data.length < 8) {
            return 'Invalid ICMP header';
        }

        const type = data[0];
        const code = data[1];

        const typeNames = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            8: 'Echo Request',
            11: 'Time Exceeded'
        };

        const typeName = typeNames[type] || `Type ${type}`;
        return `ICMP ${typeName} (Code ${code})`;
    }

    parsePcapNgFile(data) {
        console.log('Parsing PCAP-NG file...');
        
        const packets = [];
        let offset = 0;
        const interfaces = [];
        let isLittleEndian = false;

        // Section Header Block (SHB) 파싱
        if (offset + 28 > data.length) {
            throw new Error('파일이 너무 작습니다. 유효한 PCAP-NG 파일이 아닙니다.');
        }

        const shbResult = this.parseSectionHeaderBlock(data, offset);
        isLittleEndian = shbResult.isLittleEndian;
        offset = shbResult.nextOffset;
        
        console.log('Section Header Block parsed, little endian:', isLittleEndian);

        // 블록들을 순차적으로 파싱
        while (offset < data.length) {
            console.log(`Parsing block at offset ${offset}, remaining bytes: ${data.length - offset}`);
            
            if (offset + 8 > data.length) {
                console.log('Not enough bytes for block header, stopping');
                break;
            }

            const blockType = this.readUint32(data, offset, isLittleEndian);
            const blockLength = this.readUint32(data, offset + 4, isLittleEndian);
            
            console.log(`Block type: 0x${blockType.toString(16).padStart(8, '0')}, length: ${blockLength}, offset: ${offset}`);

            if (blockLength < 12 || blockLength % 4 !== 0) {
                console.warn(`Invalid block length: ${blockLength}, stopping`);
                break;
            }

            if (offset + blockLength > data.length) {
                console.warn(`Block extends beyond file length: need ${offset + blockLength}, have ${data.length}, stopping`);
                break;
            }

            // 블록 끝의 길이 필드 검증
            const endLength = this.readUint32(data, offset + blockLength - 4, isLittleEndian);
            if (endLength !== blockLength) {
                console.warn(`Block length mismatch: start=${blockLength}, end=${endLength}, continuing anyway`);
                // 일부 파일에서는 이런 경우가 있을 수 있으므로 경고만 하고 계속 진행
            }

            switch (blockType) {
                case 0x00000001: // Interface Description Block
                    const idb = this.parseInterfaceDescriptionBlock(data, offset, isLittleEndian);
                    interfaces.push(idb.interface);
                    offset = idb.nextOffset;
                    break;

                case 0x00000006: // Enhanced Packet Block
                    if (interfaces.length > 0) {
                        const epb = this.parseEnhancedPacketBlock(data, offset, isLittleEndian, interfaces);
                        if (epb.packet) {
                            packets.push(epb.packet);
                            console.log(`Added packet ${packets.length}: ${epb.packet.parsed.protocol} ${epb.packet.parsed.srcIP} -> ${epb.packet.parsed.destIP}`);
                        } else {
                            console.warn('Failed to parse Enhanced Packet Block');
                        }
                        offset = epb.nextOffset;
                    } else {
                        console.warn('Enhanced Packet Block found before Interface Description Block');
                        offset += blockLength;
                    }
                    break;

                case 0x00000003: // Simple Packet Block
                    if (interfaces.length > 0) {
                        const spb = this.parseSimplePacketBlock(data, offset, isLittleEndian, interfaces[0]);
                        if (spb.packet) {
                            packets.push(spb.packet);
                        }
                        offset = spb.nextOffset;
                    } else {
                        console.warn('Simple Packet Block found before Interface Description Block');
                        offset += blockLength;
                    }
                    break;

                case 0x00000004: // Name Resolution Block
                case 0x00000005: // Interface Statistics Block
                case 0x0000000A: // Decryption Secrets Block
                default:
                    // 지원하지 않는 블록 타입은 건너뛰기
                    console.log(`Skipping unsupported block type: 0x${blockType.toString(16)}`);
                    offset += blockLength;
                    break;
            }
        }

        console.log(`Parsed ${packets.length} packets from PCAP-NG file`);
        return packets;
    }

    parseSectionHeaderBlock(data, offset) {
        const blockType = this.readUint32(data, offset, false); // 0x0A0D0D0A
        const blockLength = this.readUint32(data, offset + 4, false);
        
        console.log(`SHB block type: 0x${blockType.toString(16)}, block length: ${blockLength}`);
        
        const byteOrderMagic = this.readUint32(data, offset + 8, false);
        console.log(`Byte order magic: 0x${byteOrderMagic.toString(16)}`);
        
        let isLittleEndian = false;
        if (byteOrderMagic === 0x1A2B3C4D) {
            isLittleEndian = false;
        } else if (byteOrderMagic === 0x4D3C2B1A) {
            isLittleEndian = true;
        } else {
            // 리틀엔디안으로 다시 시도
            const blockLengthLE = this.readUint32(data, offset + 4, true);
            const byteOrderMagicLE = this.readUint32(data, offset + 8, true);
            console.log(`Trying little endian - block length: ${blockLengthLE}, byte order: 0x${byteOrderMagicLE.toString(16)}`);
            
            if (byteOrderMagicLE === 0x1A2B3C4D) {
                isLittleEndian = false;
                return this.parseSectionHeaderBlock(data, offset); // 재귀 호출로 올바른 엔디안으로 파싱
            } else if (byteOrderMagicLE === 0x4D3C2B1A) {
                isLittleEndian = true;
                // 리틀엔디안으로 계속 진행
            } else {
                throw new Error(`Invalid byte order magic: 0x${byteOrderMagic.toString(16)} (BE) / 0x${byteOrderMagicLE.toString(16)} (LE)`);
            }
        }

        // 올바른 엔디안을 사용하여 블록 길이 다시 읽기
        const correctBlockLength = this.readUint32(data, offset + 4, isLittleEndian);
        const majorVersion = this.readUint16(data, offset + 12, isLittleEndian);
        const minorVersion = this.readUint16(data, offset + 14, isLittleEndian);
        
        console.log(`PCAP-NG version: ${majorVersion}.${minorVersion}, little endian: ${isLittleEndian}, block length: ${correctBlockLength}`);
        
        if (majorVersion !== 1) {
            throw new Error(`Unsupported PCAP-NG version: ${majorVersion}.${minorVersion}`);
        }

        return {
            isLittleEndian,
            majorVersion,
            minorVersion,
            nextOffset: offset + correctBlockLength
        };
    }

    parseInterfaceDescriptionBlock(data, offset, isLittleEndian) {
        const blockLength = this.readUint32(data, offset + 4, isLittleEndian);
        const linkType = this.readUint16(data, offset + 8, isLittleEndian);
        const snapLen = this.readUint32(data, offset + 12, isLittleEndian);

        return {
            interface: {
                linkType,
                snapLen
            },
            nextOffset: offset + blockLength
        };
    }

    parseEnhancedPacketBlock(data, offset, isLittleEndian, interfaces) {
        try {
            const blockLength = this.readUint32(data, offset + 4, isLittleEndian);
            const interfaceId = this.readUint32(data, offset + 8, isLittleEndian);
            
            // 타임스탬프 (64비트)
            const timestampHigh = this.readUint32(data, offset + 12, isLittleEndian);
            const timestampLow = this.readUint32(data, offset + 16, isLittleEndian);
            
            const capturedLength = this.readUint32(data, offset + 20, isLittleEndian);
            const originalLength = this.readUint32(data, offset + 24, isLittleEndian);

            console.log(`EPB: interface=${interfaceId}, captured=${capturedLength}, original=${originalLength}`);

            if (interfaceId >= interfaces.length) {
                console.warn(`Invalid interface ID: ${interfaceId}, available interfaces: ${interfaces.length}`);
                return { packet: null, nextOffset: offset + blockLength };
            }

            if (capturedLength === 0) {
                console.warn('Zero captured length in packet');
                return { packet: null, nextOffset: offset + blockLength };
            }

            // 패킷 데이터 추출
            const packetDataOffset = offset + 28;
            
            if (packetDataOffset + capturedLength > data.length) {
                console.warn(`Packet data extends beyond block: need ${packetDataOffset + capturedLength}, have ${data.length}`);
                return { packet: null, nextOffset: offset + blockLength };
            }

            const packetData = data.slice(packetDataOffset, packetDataOffset + capturedLength);
            
            // 타임스탬프를 마이크로초 단위로 변환 (기본값)
            const timestampValue = timestampHigh * 0x100000000 + timestampLow;
            const timestamp = new Date(timestampValue / 1000);
            
            // 이더넷 프레임 파싱
            const parsed = this.parseEthernetFrame(packetData);

            return {
                packet: {
                    timestamp,
                    capturedLength,
                    originalLength,
                    data: packetData,
                    parsed
                },
                nextOffset: offset + blockLength
            };
        } catch (error) {
            console.error('Error parsing Enhanced Packet Block:', error);
            const blockLength = this.readUint32(data, offset + 4, isLittleEndian);
            return { packet: null, nextOffset: offset + blockLength };
        }
    }

    parseSpecialCapFile(data) {
        console.log('Parsing special CAP file format...');
        console.log('File size:', data.length, 'bytes');
        console.log('First 32 bytes:', Array.from(data.slice(0, 32)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' '));
        
        try {
            const packets = [];
            
            // 여러 방법으로 파싱 시도
            const parsers = [
                () => this.parseWithFixedRecordStructure(data),
                () => this.parseWithVariableRecords(data),
                () => this.parseRawEthernetScan(data),
                () => this.parseWithCommonOffsets(data)
            ];
            
            for (const parser of parsers) {
                try {
                    const result = parser();
                    if (result && result.length > 0) {
                        console.log(`Successfully parsed ${result.length} packets using specialized parser`);
                        return result;
                    }
                } catch (error) {
                    console.log('Parser failed:', error.message);
                    continue;
                }
            }
            
            throw new Error('모든 파싱 방법이 실패했습니다.');
            
        } catch (error) {
            console.error('Error parsing special CAP file:', error);
            throw new Error('특수 CAP 파일 형식을 파싱할 수 없습니다: ' + error.message);
        }
    }

    parseWithFixedRecordStructure(data) {
        console.log('Trying fixed record structure parsing...');
        
        const packets = [];
        let offset = 0;
        
        // 파일 헤더 스킵 (다양한 크기 시도)
        const headerSizes = [0, 16, 24, 32, 64, 128];
        
        for (const headerSize of headerSizes) {
            packets.length = 0;
            offset = headerSize;
            
            while (offset + 16 < data.length) {
                // 레코드 헤더 시도 (다양한 구조)
                const recordStructures = [
                    { timestampSize: 8, lengthOffset: 8, lengthSize: 4, headerSize: 16 },
                    { timestampSize: 4, lengthOffset: 4, lengthSize: 4, headerSize: 12 },
                    { timestampSize: 8, lengthOffset: 8, lengthSize: 2, headerSize: 16 },
                    { timestampSize: 0, lengthOffset: 0, lengthSize: 4, headerSize: 4 }
                ];
                
                let packetFound = false;
                
                for (const structure of recordStructures) {
                    if (offset + structure.headerSize >= data.length) continue;
                    
                    const packetLength = structure.lengthSize === 4 ? 
                        this.readUint32(data, offset + structure.lengthOffset, true) :
                        this.readUint16(data, offset + structure.lengthOffset, true);
                    
                    if (packetLength >= 14 && packetLength <= 1518 && 
                        offset + structure.headerSize + packetLength <= data.length) {
                        
                        const packetData = data.slice(offset + structure.headerSize, 
                                                     offset + structure.headerSize + packetLength);
                        
                        if (this.looksLikeEthernetFrame(packetData, 0)) {
                            const parsed = this.parseEthernetFrame(packetData);
                            
                            packets.push({
                                timestamp: new Date(Date.now() + packets.length * 1000),
                                capturedLength: packetLength,
                                originalLength: packetLength,
                                data: packetData,
                                parsed
                            });
                            
                            offset += structure.headerSize + packetLength;
                            packetFound = true;
                            break;
                        }
                    }
                }
                
                if (!packetFound) {
                    offset += 4;
                }
                
                if (packets.length > 1000) break;
            }
            
            if (packets.length > 10) {
                console.log(`Fixed structure parsing found ${packets.length} packets with header size ${headerSize}`);
                return packets;
            }
        }
        
        return [];
    }

    parseWithVariableRecords(data) {
        console.log('Trying variable record parsing...');
        
        const packets = [];
        let offset = 16; // 일반적인 헤더 크기부터 시작
        
        while (offset < data.length - 20) {
            // TLV (Type-Length-Value) 형식 시도
            const type = this.readUint16(data, offset, true);
            const length = this.readUint16(data, offset + 2, true);
            
            if (length >= 14 && length <= 1518 && offset + 4 + length <= data.length) {
                const packetData = data.slice(offset + 4, offset + 4 + length);
                
                if (this.looksLikeEthernetFrame(packetData, 0)) {
                    const parsed = this.parseEthernetFrame(packetData);
                    
                    packets.push({
                        timestamp: new Date(Date.now() + packets.length * 1000),
                        capturedLength: length,
                        originalLength: length,
                        data: packetData,
                        parsed
                    });
                    
                    offset += 4 + length;
                    continue;
                }
            }
            
            offset += 2;
            if (packets.length > 1000) break;
        }
        
        console.log(`Variable record parsing found ${packets.length} packets`);
        return packets;
    }

    parseRawEthernetScan(data) {
        console.log('Trying raw ethernet frame scanning...');
        
        const packets = [];
        let offset = 0;
        
        while (offset < data.length - 64) {
            if (this.looksLikeEthernetFrame(data, offset)) {
                let frameLength = this.estimateFrameLength(data, offset);
                
                if (frameLength >= 64 && frameLength <= 1518) {
                    const packetData = data.slice(offset, offset + frameLength);
                    const parsed = this.parseEthernetFrame(packetData);
                    
                    // IP 패킷인지 추가 검증
                    if (parsed.protocol && (parsed.srcIP || parsed.destIP)) {
                        packets.push({
                            timestamp: new Date(Date.now() + packets.length * 1000),
                            capturedLength: frameLength,
                            originalLength: frameLength,
                            data: packetData,
                            parsed
                        });
                        
                        offset += frameLength;
                    } else {
                        offset += 1;
                    }
                } else {
                    offset += 1;
                }
            } else {
                offset += 1;
            }
            
            if (packets.length > 1000) break;
        }
        
        console.log(`Raw ethernet scanning found ${packets.length} packets`);
        return packets;
    }

    parseWithCommonOffsets(data) {
        console.log('Trying common offset patterns...');
        
        const commonOffsets = [0, 8, 16, 24, 32, 48, 64, 128, 256];
        
        for (const startOffset of commonOffsets) {
            const packets = [];
            let offset = startOffset;
            
            while (offset < data.length - 64) {
                if (this.looksLikeEthernetFrame(data, offset)) {
                    const frameLength = this.estimateFrameLength(data, offset);
                    
                    if (frameLength >= 64 && frameLength <= 1518) {
                        const packetData = data.slice(offset, offset + frameLength);
                        const parsed = this.parseEthernetFrame(packetData);
                        
                        packets.push({
                            timestamp: new Date(Date.now() + packets.length * 1000),
                            capturedLength: frameLength,
                            originalLength: frameLength,
                            data: packetData,
                            parsed
                        });
                        
                        offset += frameLength;
                        
                        // 패딩이나 헤더가 있을 수 있으므로 4바이트 정렬 확인
                        if (offset % 4 !== 0) {
                            offset = Math.ceil(offset / 4) * 4;
                        }
                    } else {
                        offset += 4;
                    }
                } else {
                    offset += 4;
                }
                
                if (packets.length > 500) break;
            }
            
            if (packets.length > 5) {
                console.log(`Common offset parsing found ${packets.length} packets with start offset ${startOffset}`);
                return packets;
            }
        }
        
        return [];
    }

    looksLikeEthernetFrame(data, offset) {
        if (offset + 14 > data.length) return false;
        
        // MAC 주소 유효성 검사 (브로드캐스트 또는 유니캐스트)
        const destMac = Array.from(data.slice(offset, offset + 6));
        const srcMac = Array.from(data.slice(offset + 6, offset + 12));
        
        // 소스 MAC이 모두 0이면 유효하지 않음
        if (srcMac.every(b => b === 0)) return false;
        
        // EtherType 필드 확인 (오프셋 12-13)
        const etherType = this.readUint16(data, offset + 12, false);
        
        // 일반적인 EtherType 값들
        const commonEtherTypes = [
            0x0800, // IPv4
            0x86DD, // IPv6
            0x0806, // ARP
            0x8100, // VLAN (802.1Q)
            0x88CC, // LLDP
            0x8847, // MPLS unicast
            0x8848, // MPLS multicast
            0x8864, // PPPoE Discovery
            0x8863, // PPPoE Session
            0x88A8, // IEEE 802.1ad (QinQ)
            0x9000, // Ethernet Configuration Testing Protocol
            0x88F7, // PTPv2
        ];
        
        if (commonEtherTypes.includes(etherType)) {
            return true;
        }
        
        // 길이 필드일 수도 있음 (802.3)
        if (etherType <= 1500) {
            // 802.3 프레임 - DSAP/SSAP 확인
            if (offset + 16 < data.length) {
                const dsap = data[offset + 14];
                const ssap = data[offset + 15];
                
                // 일반적인 SAP 값들
                if ((dsap === 0xAA && ssap === 0xAA) || // SNAP
                    (dsap === 0xFF && ssap === 0xFF) || // Novell raw 802.3
                    (dsap === 0xE0 && ssap === 0xE0)) { // NetBIOS
                    return true;
                }
            }
        }
        
        return false;
    }

    estimateFrameLength(data, offset) {
        const etherType = this.readUint16(data, offset + 12, false);
        
        // IPv4 패킷인 경우 IP 헤더에서 길이 정보 가져오기
        if (etherType === 0x0800 && offset + 20 < data.length) {
            const ipVersion = (data[offset + 14] >> 4) & 0x0F;
            if (ipVersion === 4) {
                const ipLength = this.readUint16(data, offset + 16, false);
                if (ipLength >= 20 && ipLength <= 1500) {
                    return ipLength + 14; // 이더넷 헤더 14바이트 추가
                }
            }
        }
        
        // IPv6 패킷인 경우
        if (etherType === 0x86DD && offset + 20 < data.length) {
            const ipVersion = (data[offset + 14] >> 4) & 0x0F;
            if (ipVersion === 6) {
                const payloadLength = this.readUint16(data, offset + 18, false);
                if (payloadLength <= 1460) { // IPv6 최대 페이로드
                    return payloadLength + 40 + 14; // IPv6 헤더 40바이트 + 이더넷 헤더 14바이트
                }
            }
        }
        
        // ARP 패킷인 경우 (고정 크기)
        if (etherType === 0x0806) {
            return 60; // ARP 패킷은 보통 60바이트 (패딩 포함)
        }
        
        // 802.3 프레임인 경우 길이 필드 사용
        if (etherType <= 1500) {
            return Math.min(etherType + 14, 1518);
        }
        
        // 다음 이더넷 프레임을 찾아서 길이 추정
        for (let i = offset + 64; i < Math.min(offset + 1518, data.length - 14); i += 2) {
            if (this.looksLikeEthernetFrame(data, i)) {
                const estimatedLength = i - offset;
                // 합리적인 크기인지 확인
                if (estimatedLength >= 64 && estimatedLength <= 1518) {
                    return estimatedLength;
                }
            }
        }
        
        // 파일 끝까지의 거리 확인
        const remainingBytes = data.length - offset;
        if (remainingBytes < 64) {
            return remainingBytes;
        }
        
        // 기본값: 표준 이더넷 프레임 크기들 중 하나
        const standardSizes = [64, 128, 256, 512, 1024, 1518];
        for (const size of standardSizes) {
            if (offset + size <= data.length) {
                return size;
            }
        }
        
        return Math.min(64, remainingBytes);
    }


    parseSimplePacketBlock(data, offset, isLittleEndian, interfaceInfo) {
        const blockLength = this.readUint32(data, offset + 4, isLittleEndian);
        const originalLength = this.readUint32(data, offset + 8, isLittleEndian);
        
        const packetDataOffset = offset + 12;
        const capturedLength = Math.min(originalLength, interfaceInfo.snapLen);
        
        if (packetDataOffset + capturedLength > data.length) {
            console.warn('Packet data extends beyond block');
            return { packet: null, nextOffset: offset + blockLength };
        }

        const packetData = data.slice(packetDataOffset, packetDataOffset + capturedLength);
        
        // Simple Packet Block에는 타임스탬프가 없으므로 현재 시간 사용
        const timestamp = new Date();
        
        // 이더넷 프레임 파싱
        const parsed = this.parseEthernetFrame(packetData);

        return {
            packet: {
                timestamp,
                capturedLength,
                originalLength,
                data: packetData,
                parsed
            },
            nextOffset: offset + blockLength
        };
    }

    formatMacAddress(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join(':');
    }

    formatIPv4Address(bytes) {
        return Array.from(bytes).join('.');
    }

    formatIPv6Address(bytes) {
        const parts = [];
        for (let i = 0; i < 16; i += 2) {
            parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
        }
        return parts.join(':');
    }

    readUint16(data, offset, littleEndian = false) {
        if (littleEndian) {
            return data[offset] | (data[offset + 1] << 8);
        } else {
            return (data[offset] << 8) | data[offset + 1];
        }
    }

    readUint32(data, offset, littleEndian = false) {
        if (littleEndian) {
            return (data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)) >>> 0;
        } else {
            return ((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]) >>> 0;
        }
    }

    readInt32(data, offset, littleEndian = false) {
        const uint = this.readUint32(data, offset, littleEndian);
        return uint > 0x7FFFFFFF ? uint - 0x100000000 : uint;
    }

    displayFileInfo(file) {
        const fileInfo = document.getElementById('fileInfo');
        const sizeInMB = (file.size / (1024 * 1024)).toFixed(2);
        
        fileInfo.innerHTML = `
            <h3>📄 파일 정보</h3>
            <p><strong>파일명:</strong> ${file.name}</p>
            <p><strong>크기:</strong> ${sizeInMB} MB (${file.size.toLocaleString()} bytes)</p>
            <p><strong>마지막 수정:</strong> ${file.lastModified ? new Date(file.lastModified).toLocaleString() : 'Unknown'}</p>
            <p><strong>파싱된 패킷 수:</strong> ${this.packets.length.toLocaleString()}</p>
        `;
    }

    displayStats() {
        const stats = document.getElementById('stats');
        const protocols = {};
        let totalSize = 0;

        this.packets.forEach(packet => {
            const protocol = packet.parsed.protocol;
            protocols[protocol] = (protocols[protocol] || 0) + 1;
            totalSize += packet.parsed.size;
        });

        const topProtocols = Object.entries(protocols)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5);

        const avgSize = this.packets.length > 0 ? (totalSize / this.packets.length).toFixed(1) : 0;

        stats.innerHTML = `
            <div class="stat-card">
                <div class="stat-label">총 패킷 수</div>
                <div class="stat-value">${this.packets.length.toLocaleString()}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">총 크기</div>
                <div class="stat-value">${(totalSize / 1024).toFixed(1)} KB</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">평균 패킷 크기</div>
                <div class="stat-value">${avgSize} bytes</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">주요 프로토콜</div>
                <div class="stat-value">${topProtocols.map(([protocol, count]) => `${protocol}: ${count}`).join('<br>')}</div>
            </div>
        `;
    }

    displayPackets() {
        // 페이지 변경 시 기존 상세 정보 닫기
        this.closePacketDetails();
        
        this.updatePagination();
        
        const tbody = document.getElementById('packetsBody');
        tbody.innerHTML = '';

        const startIndex = (this.currentPage - 1) * this.pageSize;
        const endIndex = Math.min(startIndex + this.pageSize, this.filteredPackets.length);
        
        for (let i = startIndex; i < endIndex; i++) {
            const packet = this.filteredPackets[i];
            const row = document.createElement('tr');
            row.dataset.packetIndex = i;
            row.innerHTML = `
                <td>${i + 1}</td>
                <td>${packet.timestamp.toLocaleTimeString()}.${packet.timestamp.getMilliseconds().toString().padStart(3, '0')}</td>
                <td>${packet.parsed.srcIP || packet.parsed.srcMac}</td>
                <td>${packet.parsed.destIP || packet.parsed.destMac}</td>
                <td>${packet.parsed.protocol}</td>
                <td>${packet.parsed.size}</td>
                <td>${packet.parsed.info}</td>
            `;
            
            row.addEventListener('click', () => this.togglePacketDetails(packet, i, row));
            tbody.appendChild(row);
        }

        this.updatePaginationInfo();
        this.updatePaginationButtons();
    }

    updatePagination() {
        this.totalPages = Math.ceil(this.filteredPackets.length / this.pageSize);
        if (this.currentPage > this.totalPages) {
            this.currentPage = Math.max(1, this.totalPages);
        }
    }

    updatePaginationInfo() {
        const paginationInfo = document.getElementById('paginationInfo');
        const startIndex = (this.currentPage - 1) * this.pageSize + 1;
        const endIndex = Math.min(this.currentPage * this.pageSize, this.filteredPackets.length);
        
        paginationInfo.textContent = `${startIndex.toLocaleString()}~${endIndex.toLocaleString()} / 총 ${this.filteredPackets.length.toLocaleString()}개 패킷`;
    }

    updatePaginationButtons() {
        const pageInfo = document.getElementById('pageInfo');
        const firstPageBtn = document.getElementById('firstPageBtn');
        const prevPageBtn = document.getElementById('prevPageBtn');
        const nextPageBtn = document.getElementById('nextPageBtn');
        const lastPageBtn = document.getElementById('lastPageBtn');
        const gotoPage = document.getElementById('gotoPage');

        pageInfo.textContent = `${this.currentPage} / ${this.totalPages}`;
        gotoPage.max = this.totalPages;

        firstPageBtn.disabled = this.currentPage === 1;
        prevPageBtn.disabled = this.currentPage === 1;
        nextPageBtn.disabled = this.currentPage === this.totalPages;
        lastPageBtn.disabled = this.currentPage === this.totalPages;
    }

    goToPage(page) {
        if (page >= 1 && page <= this.totalPages) {
            this.currentPage = page;
            this.displayPackets();
        }
    }

    handlePageSizeChange() {
        const pageSize = document.getElementById('pageSize');
        this.pageSize = parseInt(pageSize.value);
        this.currentPage = 1;
        this.displayPackets();
    }

    handleGotoPage() {
        const gotoPage = document.getElementById('gotoPage');
        const page = parseInt(gotoPage.value);
        if (page) {
            this.goToPage(page);
            gotoPage.value = '';
        }
    }

    toggleSearchHelp() {
        const searchHelp = document.getElementById('searchHelp');
        const isVisible = searchHelp.style.display !== 'none';
        searchHelp.style.display = isVisible ? 'none' : 'block';
    }

    togglePacketDetails(packet, index, clickedRow) {
        // 이미 같은 행이 선택되어 있다면 닫기
        if (this.selectedPacketRow === clickedRow) {
            this.closePacketDetails();
            return;
        }

        // 기존 상세 정보가 있다면 닫기
        this.closePacketDetails();

        // 새로운 행 선택
        this.selectedPacketRow = clickedRow;
        clickedRow.classList.add('selected');

        // 상세 정보 행 생성
        const detailsRow = document.createElement('tr');
        detailsRow.classList.add('packet-details-row');
        
        const hexDump = this.createHexDump(packet.data);
        
        const detailsContent = `패킷 #${index + 1} 상세 정보:

시간: ${packet.timestamp.toLocaleString()}.${packet.timestamp.getMilliseconds().toString().padStart(3, '0')}
캡처된 길이: ${packet.capturedLength} bytes
원본 길이: ${packet.originalLength} bytes

이더넷 프레임:
  소스 MAC: ${packet.parsed.srcMac}
  목적지 MAC: ${packet.parsed.destMac}
  프로토콜: ${packet.parsed.protocol}
  소스 IP: ${packet.parsed.srcIP}
  목적지 IP: ${packet.parsed.destIP}
  정보: ${packet.parsed.info}

Hex Dump:
${hexDump}`;

        detailsRow.innerHTML = `
            <td colspan="7">
                <div class="packet-details-header">
                    패킷 #${index + 1} 상세 정보
                    <button class="close-details" onclick="analyzer.closePacketDetails()">✕</button>
                </div>
                <div class="packet-details-content">${detailsContent}</div>
            </td>
        `;

        // 클릭된 행 바로 다음에 상세 정보 행 삽입
        clickedRow.parentNode.insertBefore(detailsRow, clickedRow.nextSibling);
        this.currentDetailsRow = detailsRow;

        // 상세 정보로 부드럽게 스크롤
        setTimeout(() => {
            detailsRow.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 100);
    }

    closePacketDetails() {
        // 선택된 행 하이라이트 제거
        if (this.selectedPacketRow) {
            this.selectedPacketRow.classList.remove('selected');
            this.selectedPacketRow = null;
        }

        // 상세 정보 행 제거
        if (this.currentDetailsRow) {
            this.currentDetailsRow.remove();
            this.currentDetailsRow = null;
        }
    }

    showPacketDetails(packet, index) {
        // 기존 메서드는 호환성을 위해 유지하지만 사용하지 않음
        const detailsDiv = document.getElementById('packetDetails');
        const contentDiv = document.getElementById('packetDetailsContent');
        
        const hexDump = this.createHexDump(packet.data);
        
        contentDiv.innerHTML = `패킷 #${index + 1} 상세 정보:

시간: ${packet.timestamp.toLocaleString()}.${packet.timestamp.getMilliseconds().toString().padStart(3, '0')}
캡처된 길이: ${packet.capturedLength} bytes
원본 길이: ${packet.originalLength} bytes

이더넷 프레임:
  소스 MAC: ${packet.parsed.srcMac}
  목적지 MAC: ${packet.parsed.destMac}
  프로토콜: ${packet.parsed.protocol}
  소스 IP: ${packet.parsed.srcIP}
  목적지 IP: ${packet.parsed.destIP}
  정보: ${packet.parsed.info}

Hex Dump:
${hexDump}`;
        
        detailsDiv.style.display = 'block';
        detailsDiv.scrollIntoView({ behavior: 'smooth' });
    }

    createHexDump(data) {
        let result = '';
        for (let i = 0; i < data.length; i += 16) {
            const offset = i.toString(16).padStart(8, '0');
            const hexBytes = [];
            const asciiBytes = [];
            
            for (let j = 0; j < 16; j++) {
                if (i + j < data.length) {
                    const byte = data[i + j];
                    hexBytes.push(byte.toString(16).padStart(2, '0'));
                    asciiBytes.push(byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.');
                } else {
                    hexBytes.push('  ');
                    asciiBytes.push(' ');
                }
            }
            
            result += `${offset}  ${hexBytes.slice(0, 8).join(' ')}  ${hexBytes.slice(8).join(' ')}  |${asciiBytes.join('')}|\n`;
        }
        return result;
    }

    handleSearch() {
        const searchTerm = document.getElementById('searchBox').value.trim();
        
        if (!searchTerm) {
            this.filteredPackets = this.packets;
        } else {
            this.filteredPackets = this.packets.filter(packet => this.matchesSearchQuery(packet, searchTerm));
        }
        
        this.currentPage = 1;
        this.displayPackets();
    }

    matchesSearchQuery(packet, query) {
        const lowerQuery = query.toLowerCase();
        
        // AND/OR 논리 연산자 처리
        if (lowerQuery.includes(' and ')) {
            return lowerQuery.split(' and ').every(term => this.matchesSingleQuery(packet, term.trim()));
        } else if (lowerQuery.includes(' or ')) {
            return lowerQuery.split(' or ').some(term => this.matchesSingleQuery(packet, term.trim()));
        } else {
            return this.matchesSingleQuery(packet, lowerQuery);
        }
    }

    matchesSingleQuery(packet, query) {
        // 필드별 검색 처리
        if (query.includes(':')) {
            const [field, value] = query.split(':', 2);
            return this.matchesFieldQuery(packet, field.trim(), value.trim());
        }
        
        // 일반 검색
        const searchableText = [
            packet.parsed.srcIP,
            packet.parsed.destIP,
            packet.parsed.srcMac,
            packet.parsed.destMac,
            packet.parsed.protocol,
            packet.parsed.info
        ].join(' ').toLowerCase();
        
        return searchableText.includes(query);
    }

    matchesFieldQuery(packet, field, value) {
        switch (field.toLowerCase()) {
            case 'src':
            case 'source':
                return packet.parsed.srcIP.toLowerCase().includes(value) || 
                       packet.parsed.srcMac.toLowerCase().includes(value);
                       
            case 'dst':
            case 'dest':
            case 'destination':
                return packet.parsed.destIP.toLowerCase().includes(value) || 
                       packet.parsed.destMac.toLowerCase().includes(value);
                       
            case 'ip':
                return packet.parsed.srcIP.toLowerCase().includes(value) || 
                       packet.parsed.destIP.toLowerCase().includes(value);
                       
            case 'mac':
                return packet.parsed.srcMac.toLowerCase().includes(value) || 
                       packet.parsed.destMac.toLowerCase().includes(value);
                       
            case 'protocol':
            case 'proto':
                return packet.parsed.protocol.toLowerCase().includes(value);
                
            case 'port':
                const portRegex = /(\d+)/g;
                const infoMatches = packet.parsed.info.match(portRegex);
                if (infoMatches) {
                    return infoMatches.some(port => port === value);
                }
                return false;
                
            case 'size':
                return this.matchesSizeQuery(packet.parsed.size, value);
                
            case 'info':
                return packet.parsed.info.toLowerCase().includes(value);
                
            default:
                return false;
        }
    }

    matchesSizeQuery(packetSize, query) {
        // 크기 조건 처리 (>, <, =, >=, <=)
        if (query.startsWith('>=')) {
            return packetSize >= parseInt(query.substring(2));
        } else if (query.startsWith('<=')) {
            return packetSize <= parseInt(query.substring(2));
        } else if (query.startsWith('>')) {
            return packetSize > parseInt(query.substring(1));
        } else if (query.startsWith('<')) {
            return packetSize < parseInt(query.substring(1));
        } else if (query.startsWith('=')) {
            return packetSize === parseInt(query.substring(1));
        } else {
            return packetSize === parseInt(query);
        }
    }

    handleClear() {
        document.getElementById('searchBox').value = '';
        this.filteredPackets = this.packets;
        this.currentPage = 1;
        this.closePacketDetails();
        this.displayPackets();
        document.getElementById('packetDetails').style.display = 'none';
        document.getElementById('searchHelp').style.display = 'none';
    }

    handleExport() {
        const csvContent = this.generateCSV();
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `pcap_analysis_${new Date().toISOString().slice(0, 10)}.csv`;
        link.click();
    }

    generateCSV() {
        const headers = ['번호', '시간', '소스IP', '목적지IP', '소스MAC', '목적지MAC', '프로토콜', '크기', '정보'];
        const rows = [headers.join(',')];
        
        this.filteredPackets.forEach((packet, index) => {
            const row = [
                index + 1,
                packet.timestamp.toISOString(),
                `"${packet.parsed.srcIP}"`,
                `"${packet.parsed.destIP}"`,
                `"${packet.parsed.srcMac}"`,
                `"${packet.parsed.destMac}"`,
                `"${packet.parsed.protocol}"`,
                packet.parsed.size,
                `"${packet.parsed.info.replace(/"/g, '""')}"`
            ];
            rows.push(row.join(','));
        });
        
        return rows.join('\n');
    }

    showAnalysisSection() {
        document.getElementById('analysisSection').style.display = 'block';
    }

    showLoading(show) {
        document.getElementById('loadingIndicator').style.display = show ? 'block' : 'none';
    }

    showError(message) {
        const errorDiv = document.getElementById('errorMessage');
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
    }

    hideError() {
        document.getElementById('errorMessage').style.display = 'none';
    }
}

let analyzer;

document.addEventListener('DOMContentLoaded', () => {
    analyzer = new PcapAnalyzer();
});