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
        this.tcpStreams = [];
        this.httpSessions = [];
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const searchBtn = document.getElementById('searchBtn');
        const clearBtn = document.getElementById('clearBtn');
        const helpBtn = document.getElementById('helpBtn');
        const tcpStreamBtn = document.getElementById('tcpStreamBtn');
        const httpAnalysisBtn = document.getElementById('httpAnalysisBtn');
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

        // TCP Stream 관련 요소들
        const closeTcpStreamModal = document.getElementById('closeTcpStreamModal');
        const streamSelect = document.getElementById('streamSelect');
        const saveStreamBtn = document.getElementById('saveStreamBtn');
        const streamViewRadios = document.getElementsByName('streamView');

        // HTTP 분석 관련 요소들
        const closeHttpAnalysisModal = document.getElementById('closeHttpAnalysisModal');
        const httpSessionSelect = document.getElementById('httpSessionSelect');
        const saveHttpBtn = document.getElementById('saveHttpBtn');
        const httpViewRadios = document.getElementsByName('httpView');

        uploadArea.addEventListener('click', () => fileInput.click());
        uploadArea.addEventListener('dragover', this.handleDragOver.bind(this));
        uploadArea.addEventListener('dragleave', this.handleDragLeave.bind(this));
        uploadArea.addEventListener('drop', this.handleDrop.bind(this));
        
        fileInput.addEventListener('change', this.handleFileSelect.bind(this));
        searchBtn.addEventListener('click', this.handleSearch.bind(this));
        clearBtn.addEventListener('click', this.handleClear.bind(this));
        helpBtn.addEventListener('click', this.toggleSearchHelp.bind(this));
        tcpStreamBtn.addEventListener('click', this.openTcpStreamAnalysis.bind(this));
        httpAnalysisBtn.addEventListener('click', this.openHttpAnalysis.bind(this));
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

        // TCP Stream 이벤트 리스너
        closeTcpStreamModal.addEventListener('click', this.closeTcpStreamModal.bind(this));
        streamSelect.addEventListener('change', this.handleStreamSelect.bind(this));
        saveStreamBtn.addEventListener('click', this.saveCurrentStream.bind(this));
        
        for (const radio of streamViewRadios) {
            radio.addEventListener('change', this.updateStreamView.bind(this));
        }

        // HTTP 분석 이벤트 리스너
        closeHttpAnalysisModal.addEventListener('click', this.closeHttpAnalysisModal.bind(this));
        httpSessionSelect.addEventListener('change', this.handleHttpSessionSelect.bind(this));
        saveHttpBtn.addEventListener('click', this.saveCurrentHttpSession.bind(this));
        
        for (const radio of httpViewRadios) {
            radio.addEventListener('change', this.updateHttpView.bind(this));
        }
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
            
            // TCP Stream 분석
            this.analyzeTcpStreams();
            
            // HTTP 세션 분석
            this.analyzeHttpSessions();
            
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
                const tcpResult = this.parseTCP(data.slice(headerLength));
                
                // HTTP 트래픽 감지
                if (tcpResult.payload && tcpResult.payload.length > 0) {
                    // 간단한 ASCII 변환
                    let ascii = '';
                    for (let i = 0; i < Math.min(tcpResult.payload.length, 100); i++) {
                        const byte = tcpResult.payload[i];
                        if (byte >= 32 && byte <= 126) {
                            ascii += String.fromCharCode(byte);
                        } else {
                            ascii += '.';
                        }
                    }
                    
                    // HTTP 메소드 확인
                    const httpMethods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS '];
                    const isHttpReq = httpMethods.some(method => ascii.startsWith(method));
                    const isHttpResp = ascii.startsWith('HTTP/');
                    
                    // HTTP 포트 확인
                    const httpPorts = [80, 443, 8080, 8081, 8443, 3000, 3001, 5000, 9000];
                    const isHttpPortSrc = httpPorts.includes(tcpResult.srcPort);
                    const isHttpPortDest = httpPorts.includes(tcpResult.destPort);
                    
                    if (isHttpReq || isHttpResp || isHttpPortSrc || isHttpPortDest) {
                        protocolName = 'HTTP';
                        info = `HTTP ${tcpResult.srcPort} → ${tcpResult.destPort}`;
                        if (isHttpReq) {
                            const method = ascii.split(' ')[0];
                            info += ` [${method} Request]`;
                        } else if (isHttpResp) {
                            const statusMatch = ascii.match(/HTTP\/\d\.\d (\d{3})/);
                            if (statusMatch) {
                                info += ` [${statusMatch[1]} Response]`;
                            } else {
                                info += ` [Response]`;
                            }
                        }
                    } else {
                        protocolName = 'TCP';
                        info = tcpResult.info;
                    }
                } else {
                    protocolName = 'TCP';
                    info = tcpResult.info;
                }
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
        const headerLength = ((data[12] >> 4) & 0x0F) * 4;

        const flagNames = [];
        if (flags & 0x01) flagNames.push('FIN');
        if (flags & 0x02) flagNames.push('SYN');
        if (flags & 0x04) flagNames.push('RST');
        if (flags & 0x08) flagNames.push('PSH');
        if (flags & 0x10) flagNames.push('ACK');
        if (flags & 0x20) flagNames.push('URG');

        // TCP 페이로드에서 HTTP 트래픽 감지
        let tcpPayload = null;
        if (data.length > headerLength) {
            tcpPayload = data.slice(headerLength);
        }

        return {
            srcPort,
            destPort,
            flags: flagNames,
            payload: tcpPayload,
            info: `TCP ${srcPort} → ${destPort} [${flagNames.join(', ')}]`
        };
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
        // 사용자에게 내보내기 형식 선택하도록 함
        const format = this.selectExportFormat();
        
        if (format === 'csv') {
            this.exportAsCSV();
        } else if (format === 'json') {
            this.exportAsJSON();
        } else if (format === 'txt') {
            this.exportAsText();
        }
    }

    selectExportFormat() {
        const choice = prompt(
            "내보내기 형식을 선택하세요:\n" +
            "1 - CSV (Excel 호환)\n" + 
            "2 - JSON\n" +
            "3 - 텍스트\n" +
            "\n번호를 입력하세요 (기본값: 1):"
        );
        
        switch (choice) {
            case '2': return 'json';
            case '3': return 'txt';
            default: return 'csv';
        }
    }

    exportAsCSV() {
        const csvContent = this.generateCSV();
        // UTF-8 BOM 추가하여 Excel에서 한글이 올바르게 표시되도록 함
        const BOM = '\uFEFF';
        const blob = new Blob([BOM + csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `pcap_analysis_${new Date().toISOString().slice(0, 10)}.csv`;
        link.click();
        URL.revokeObjectURL(link.href);
    }

    exportAsJSON() {
        const jsonData = {
            exportInfo: {
                filename: this.currentFile?.name || 'unknown',
                exportDate: new Date().toISOString(),
                totalPackets: this.packets.length,
                filteredPackets: this.filteredPackets.length
            },
            packets: this.filteredPackets.map((packet, index) => ({
                number: index + 1,
                timestamp: this.formatTimestampWithMicroseconds(packet.timestamp),
                timestampISO: packet.timestamp.toISOString(),
                sourceIP: packet.parsed.srcIP,
                destinationIP: packet.parsed.destIP,
                sourceMAC: packet.parsed.srcMac,
                destinationMAC: packet.parsed.destMac,
                protocol: packet.parsed.protocol,
                size: packet.parsed.size,
                info: packet.parsed.info,
                capturedLength: packet.capturedLength,
                originalLength: packet.originalLength
            }))
        };

        const jsonContent = JSON.stringify(jsonData, null, 2);
        const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `pcap_analysis_${new Date().toISOString().slice(0, 10)}.json`;
        link.click();
        URL.revokeObjectURL(link.href);
    }

    exportAsText() {
        let textContent = `PCAP 파일 분석 결과\n`;
        textContent += `파일명: ${this.currentFile?.name || 'unknown'}\n`;
        textContent += `내보내기 날짜: ${new Date().toLocaleString()}\n`;
        textContent += `총 패킷 수: ${this.packets.length}\n`;
        textContent += `필터된 패킷 수: ${this.filteredPackets.length}\n`;
        textContent += '='.repeat(100) + '\n\n';

        this.filteredPackets.forEach((packet, index) => {
            textContent += `패킷 #${index + 1}\n`;
            textContent += `  시간: ${this.formatTimestampWithMicroseconds(packet.timestamp)}\n`;
            textContent += `  소스: ${packet.parsed.srcIP || packet.parsed.srcMac}\n`;
            textContent += `  목적지: ${packet.parsed.destIP || packet.parsed.destMac}\n`;
            textContent += `  프로토콜: ${packet.parsed.protocol}\n`;
            textContent += `  크기: ${packet.parsed.size} bytes\n`;
            textContent += `  정보: ${packet.parsed.info}\n`;
            textContent += '-'.repeat(80) + '\n';
        });

        const blob = new Blob([textContent], { type: 'text/plain;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `pcap_analysis_${new Date().toISOString().slice(0, 10)}.txt`;
        link.click();
        URL.revokeObjectURL(link.href);
    }

    generateCSV() {
        const headers = ['번호', '시간', '소스IP', '목적지IP', '소스MAC', '목적지MAC', '프로토콜', '크기', '정보'];
        
        // CSV 셀 값을 안전하게 이스케이프하는 함수
        const escapeCsvValue = (value) => {
            if (value === null || value === undefined) return '';
            
            const stringValue = String(value);
            
            // 쉼표, 줄바꿈, 따옴표가 포함된 경우 따옴표로 감싸고 내부 따옴표는 이중화
            if (stringValue.includes(',') || stringValue.includes('\n') || stringValue.includes('\r') || stringValue.includes('"')) {
                return `"${stringValue.replace(/"/g, '""')}"`;
            }
            
            return stringValue;
        };
        
        // 헤더 행 생성
        const csvRows = [headers.map(escapeCsvValue).join(',')];
        
        // 데이터 행 생성
        this.filteredPackets.forEach((packet, index) => {
            const row = [
                index + 1,
                this.formatTimestampWithMicroseconds(packet.timestamp),
                packet.parsed.srcIP || '',
                packet.parsed.destIP || '',
                packet.parsed.srcMac || '',
                packet.parsed.destMac || '',
                packet.parsed.protocol || '',
                packet.parsed.size || 0,
                packet.parsed.info || ''
            ];
            
            csvRows.push(row.map(escapeCsvValue).join(','));
        });
        
        return csvRows.join('\r\n'); // Windows 스타일 줄바꿈 사용
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

    analyzeTcpStreams() {
        console.log('=== Analyzing TCP streams ===');
        this.tcpStreams = [];
        const streamMap = new Map();

        // 먼저 패킷 크기 분포 확인
        const tcpHttpPackets = this.packets.filter(p => p.parsed.protocol === 'TCP' || p.parsed.protocol === 'HTTP');
        const packetSizes = tcpHttpPackets.map(p => p.capturedLength);
        
        console.log(`Total TCP/HTTP packets: ${tcpHttpPackets.length}`);
        console.log(`TCP/HTTP packet sizes: min=${Math.min(...packetSizes)}, max=${Math.max(...packetSizes)}, avg=${Math.round(packetSizes.reduce((a,b) => a+b, 0) / packetSizes.length)}`);
        
        // 큰 패킷들 (HTTP 데이터가 있을 가능성이 높음) 먼저 확인
        const largePackets = tcpHttpPackets.filter(p => p.capturedLength > 100);
        console.log(`Found ${largePackets.length} large TCP/HTTP packets (>100 bytes)`);
        
        // HTTP 프로토콜 패킷 확인
        const httpProtocolPackets = this.packets.filter(p => p.parsed.protocol === 'HTTP');
        console.log(`Found ${httpProtocolPackets.length} packets already classified as HTTP protocol`);

        // TCP 패킷만 필터링하고 스트림별로 그룹화
        this.packets.forEach((packet, index) => {
            if (packet.parsed.protocol === 'TCP' || packet.parsed.protocol === 'HTTP') {
                const tcpInfo = this.extractTcpInfo(packet);
                if (tcpInfo) {
                    const streamKey = this.getTcpStreamKey(tcpInfo);
                    
                    if (!streamMap.has(streamKey)) {
                        streamMap.set(streamKey, {
                            id: streamMap.size,
                            key: streamKey,
                            srcIP: tcpInfo.srcIP,
                            srcPort: tcpInfo.srcPort,
                            destIP: tcpInfo.destIP,
                            destPort: tcpInfo.destPort,
                            packets: [],
                            totalBytes: 0,
                            startTime: packet.timestamp,
                            endTime: packet.timestamp,
                            isHttpStream: this.isHttpPort(tcpInfo.srcPort) || this.isHttpPort(tcpInfo.destPort) || packet.parsed.protocol === 'HTTP',
                            hasLargePackets: false
                        });
                    }

                    const stream = streamMap.get(streamKey);
                    const tcpData = this.extractTcpData(packet, tcpInfo);
                    
                    // 큰 패킷인지 확인
                    if (packet.capturedLength > 100) {
                        stream.hasLargePackets = true;
                        console.log(`Large packet in stream ${stream.id}: ${packet.capturedLength} bytes, extracted ${tcpData.length} bytes`);
                    }
                    
                    stream.packets.push({
                        index,
                        packet,
                        tcpInfo,
                        direction: this.getTcpDirection(tcpInfo, stream),
                        data: tcpData,
                        packetSize: packet.capturedLength
                    });
                    
                    stream.totalBytes += tcpData.length;
                    stream.endTime = packet.timestamp;
                    
                    // HTTP 트래픽 감지
                    if (tcpData.length > 0) {
                        const ascii = this.bytesToAscii(tcpData);
                        if (this.isHttpRequest(ascii) || this.isHttpResponse(ascii)) {
                            stream.isHttpStream = true;
                            console.log(`HTTP content detected in stream ${stream.id}`);
                        }
                    }
                }
            }
        });

        this.tcpStreams = Array.from(streamMap.values())
            .filter(stream => stream.packets.length > 1) // 최소 2개 패킷 이상
            .sort((a, b) => a.startTime - b.startTime);

        // 스트림별 상세 정보 로깅
        this.tcpStreams.forEach(stream => {
            const dataPackets = stream.packets.filter(p => p.data.length > 0).length;
            const largePackets = stream.packets.filter(p => p.packetSize > 100).length;
            console.log(`Stream ${stream.id}: ${stream.packets.length} packets, ${dataPackets} with data, ${largePackets} large packets, isHTTP: ${stream.isHttpStream}`);
        });

        console.log(`Found ${this.tcpStreams.length} TCP streams (${this.tcpStreams.filter(s => s.isHttpStream).length} HTTP streams)`);
    }

    extractTcpInfo(packet) {
        try {
            const parsed = packet.parsed;
            if (!parsed.srcIP || !parsed.destIP) return null;

            // TCP 정보를 패킷 정보에서 추출
            const info = parsed.info;
            let tcpMatch = null;
            let srcPort = 0;
            let destPort = 0;
            
            // TCP 패킷인 경우
            if (parsed.protocol === 'TCP') {
                tcpMatch = info.match(/TCP (\d+) → (\d+)/);
                if (tcpMatch) {
                    srcPort = parseInt(tcpMatch[1]);
                    destPort = parseInt(tcpMatch[2]);
                }
            }
            // HTTP 패킷인 경우 (이미 HTTP로 분류된 경우)
            else if (parsed.protocol === 'HTTP') {
                // HTTP 정보에서 포트 추출
                const httpMatch = info.match(/HTTP (\d+) → (\d+)/);
                if (httpMatch) {
                    srcPort = parseInt(httpMatch[1]);
                    destPort = parseInt(httpMatch[2]);
                    console.log(`Extracting TCP info from HTTP packet: ${srcPort} → ${destPort}`);
                } else {
                    // 기본 HTTP 포트 추정
                    srcPort = 80;
                    destPort = 80;
                    console.log(`Using default ports for HTTP packet`);
                }
            }
            
            if (srcPort > 0 && destPort > 0) {
                return {
                    srcIP: parsed.srcIP,
                    destIP: parsed.destIP,
                    srcPort: srcPort,
                    destPort: destPort,
                    flags: this.parseTcpFlags(info),
                    dataLength: this.estimateTcpDataLength(packet)
                };
            }
            return null;
        } catch (error) {
            console.error('Error extracting TCP info:', error);
            return null;
        }
    }

    parseTcpFlags(info) {
        const flags = [];
        if (info.includes('SYN')) flags.push('SYN');
        if (info.includes('ACK')) flags.push('ACK');
        if (info.includes('FIN')) flags.push('FIN');
        if (info.includes('RST')) flags.push('RST');
        if (info.includes('PSH')) flags.push('PSH');
        if (info.includes('URG')) flags.push('URG');
        return flags;
    }

    estimateTcpDataLength(packet) {
        // TCP 헤더는 보통 20바이트, 이더넷 헤더 14바이트, IP 헤더 20바이트
        const headerSize = 54; // 추정값
        return Math.max(0, packet.capturedLength - headerSize);
    }

    getTcpStreamKey(tcpInfo) {
        // 양방향 스트림을 하나로 식별하기 위해 정렬된 키 생성
        const endpoint1 = `${tcpInfo.srcIP}:${tcpInfo.srcPort}`;
        const endpoint2 = `${tcpInfo.destIP}:${tcpInfo.destPort}`;
        return endpoint1 < endpoint2 ? `${endpoint1}-${endpoint2}` : `${endpoint2}-${endpoint1}`;
    }

    getTcpDirection(tcpInfo, stream) {
        // 첫 번째 패킷의 방향을 client로 설정
        if (stream.packets.length === 0) return 'client';
        
        const firstPacket = stream.packets[0].tcpInfo;
        const isClientToServer = (tcpInfo.srcIP === firstPacket.srcIP && tcpInfo.srcPort === firstPacket.srcPort);
        return isClientToServer ? 'client' : 'server';
    }

    isHttpPort(port) {
        // 일반적인 HTTP 포트들
        const httpPorts = [80, 443, 8080, 8081, 8443, 3000, 3001, 5000, 9000];
        return httpPorts.includes(port);
    }

    extractTcpData(packet, tcpInfo) {
        // TCP 데이터 추출 - 여러 방법 시도
        console.log(`Extracting TCP data from ${packet.parsed.protocol} packet of length ${packet.data.length}`);
        
        // HTTP 프로토콜로 이미 분류된 패킷은 직접 HTTP 데이터 추출 시도
        if (packet.parsed.protocol === 'HTTP') {
            console.log('Trying HTTP packet data extraction...');
            
            // HTTP 패킷에서 직접 HTTP 데이터 찾기
            for (let offset = 0; offset < Math.min(200, packet.data.length - 50); offset++) {
                const testData = packet.data.slice(offset);
                if (testData.length > 20) {
                    const ascii = this.simpleAscii(testData.slice(0, 50));
                    if (ascii.startsWith('GET ') || ascii.startsWith('POST ') || ascii.startsWith('HTTP/') ||
                        ascii.includes('Host:') || ascii.includes('User-Agent:')) {
                        console.log(`HTTP packet: Found HTTP data at offset ${offset}, extracted ${testData.length} bytes: ${ascii}`);
                        return testData;
                    }
                }
            }
        }
        
        // 방법 1: 정확한 헤더 계산
        try {
            let headerSize = 14; // Ethernet header
            
            if (packet.data.length > 34) {
                // IP 헤더 크기
                const ipHeaderLength = (packet.data[14] & 0x0F) * 4;
                headerSize += ipHeaderLength;
                
                // TCP 헤더 크기
                if (packet.data.length > headerSize + 12) {
                    const tcpHeaderLength = ((packet.data[headerSize + 12] >> 4) & 0x0F) * 4;
                    headerSize += tcpHeaderLength;
                    
                    if (packet.data.length > headerSize) {
                        const tcpData = packet.data.slice(headerSize);
                        console.log(`Method 1: Extracted ${tcpData.length} bytes (headerSize: ${headerSize})`);
                        if (tcpData.length > 0) {
                            return tcpData;
                        }
                    }
                }
            }
        } catch (error) {
            console.log('Method 1 failed:', error);
        }
        
        // 방법 2: 다양한 고정 크기 시도
        const headerSizes = [54, 60, 66, 74]; // 일반적인 헤더 크기들
        
        for (const headerSize of headerSizes) {
            if (packet.data.length > headerSize) {
                const tcpData = packet.data.slice(headerSize);
                
                // 데이터가 HTTP 같아 보이는지 확인
                if (tcpData.length > 10) {
                    const ascii = this.simpleAscii(tcpData.slice(0, 20));
                    if (ascii.includes('GET') || ascii.includes('POST') || ascii.includes('HTTP') || 
                        ascii.includes('Host:') || ascii.includes('Content-')) {
                        console.log(`Method 2: Found HTTP-like data with headerSize ${headerSize}, extracted ${tcpData.length} bytes: ${ascii}`);
                        return tcpData;
                    }
                }
            }
        }
        
        // 방법 3: 전체 패킷에서 HTTP 패턴 검색 (큰 패킷은 더 넓은 범위 검색)
        const searchLimit = packet.data.length > 200 ? 200 : 100;
        if (packet.data.length > 20) {
            for (let offset = 14; offset < Math.min(searchLimit, packet.data.length - 20); offset++) {
                const testData = packet.data.slice(offset);
                if (testData.length > 10) {
                    const ascii = this.simpleAscii(testData.slice(0, 30));
                    if (ascii.startsWith('GET ') || ascii.startsWith('POST ') || ascii.startsWith('PUT ') ||
                        ascii.startsWith('HTTP/') || ascii.includes('Host: ') || ascii.includes('User-Agent: ')) {
                        console.log(`Method 3: Found HTTP at offset ${offset}, extracted ${testData.length} bytes: ${ascii}`);
                        return testData;
                    }
                }
            }
        }
        
        // 방법 4: 큰 패킷에서 더 많은 패턴 시도
        if (packet.data.length > 200) {
            console.log(`Large packet (${packet.data.length} bytes) - trying more patterns`);
            for (let offset = 0; offset < Math.min(300, packet.data.length - 50); offset += 2) {
                const testData = packet.data.slice(offset, offset + 100);
                const ascii = this.simpleAscii(testData);
                if (ascii.includes('HTTP') || ascii.includes('GET') || ascii.includes('POST') || 
                    ascii.includes('Content-Length') || ascii.includes('Content-Type')) {
                    const fullData = packet.data.slice(offset);
                    console.log(`Method 4: Found HTTP pattern at offset ${offset}, extracted ${fullData.length} bytes: ${ascii.substring(0, 50)}`);
                    return fullData;
                }
            }
        }
        
        console.log('No TCP data extracted');
        return new Uint8Array(0);
    }

    simpleAscii(data) {
        let result = '';
        for (let i = 0; i < Math.min(data.length, 50); i++) {
            const byte = data[i];
            if (byte >= 32 && byte <= 126) {
                result += String.fromCharCode(byte);
            } else {
                result += '.';
            }
        }
        return result;
    }

    openTcpStreamAnalysis() {
        if (this.tcpStreams.length === 0) {
            alert('TCP 스트림이 발견되지 않았습니다. TCP 패킷이 포함된 캡처 파일을 분석해주세요.');
            return;
        }

        // 스트림 목록 업데이트
        const streamSelect = document.getElementById('streamSelect');
        streamSelect.innerHTML = '<option value="">스트림을 선택하세요</option>';
        
        this.tcpStreams.forEach(stream => {
            const option = document.createElement('option');
            option.value = stream.id;
            option.textContent = `Stream ${stream.id}: ${stream.srcIP}:${stream.srcPort} ↔ ${stream.destIP}:${stream.destPort} (${stream.packets.length} packets, ${stream.totalBytes} bytes)`;
            streamSelect.appendChild(option);
        });

        // 모달 표시
        document.getElementById('tcpStreamModal').style.display = 'flex';
    }

    closeTcpStreamModal() {
        document.getElementById('tcpStreamModal').style.display = 'none';
    }

    handleStreamSelect() {
        const streamSelect = document.getElementById('streamSelect');
        const streamId = parseInt(streamSelect.value);
        
        if (isNaN(streamId)) {
            document.getElementById('streamData').textContent = 'TCP 스트림을 선택하면 여기에 데이터가 표시됩니다.';
            document.getElementById('streamInfo').textContent = '';
            return;
        }

        const stream = this.tcpStreams[streamId];
        if (stream) {
            const info = `${stream.packets.length} packets, ${stream.totalBytes} bytes, ${((stream.endTime - stream.startTime) / 1000).toFixed(2)}s duration`;
            document.getElementById('streamInfo').textContent = info;
            this.updateStreamView();
        }
    }

    updateStreamView() {
        const streamSelect = document.getElementById('streamSelect');
        const streamId = parseInt(streamSelect.value);
        
        if (isNaN(streamId)) return;
        
        const stream = this.tcpStreams[streamId];
        if (!stream) return;

        const viewMode = document.querySelector('input[name="streamView"]:checked').value;
        const streamData = document.getElementById('streamData');
        
        let content = '';
        
        switch (viewMode) {
            case 'ascii':
                content = this.generateAsciiView(stream);
                break;
            case 'hex':
                content = this.generateHexView(stream);
                break;
            case 'raw':
                content = this.generateRawView(stream);
                break;
        }
        
        streamData.innerHTML = content;
    }

    generateAsciiView(stream) {
        let html = '';
        
        stream.packets.forEach((streamPacket, index) => {
            if (streamPacket.data.length > 0) {
                const direction = streamPacket.direction;
                const timestamp = streamPacket.packet.timestamp.toLocaleTimeString();
                const ascii = this.bytesToAscii(streamPacket.data);
                
                html += `<div class="stream-packet ${direction}">`;
                html += `<div class="stream-packet-header">${direction.toUpperCase()} → Packet #${streamPacket.index + 1} (${timestamp}) - ${streamPacket.data.length} bytes</div>`;
                html += `<div class="stream-packet-data">${this.escapeHtml(ascii)}</div>`;
                html += `</div>`;
            }
        });
        
        return html || '<div>이 스트림에는 표시할 데이터가 없습니다.</div>';
    }

    generateHexView(stream) {
        let html = '';
        
        stream.packets.forEach((streamPacket, index) => {
            if (streamPacket.data.length > 0) {
                const direction = streamPacket.direction;
                const timestamp = streamPacket.packet.timestamp.toLocaleTimeString();
                const hexDump = this.createHexDump(streamPacket.data);
                
                html += `<div class="stream-packet ${direction}">`;
                html += `<div class="stream-packet-header">${direction.toUpperCase()} → Packet #${streamPacket.index + 1} (${timestamp}) - ${streamPacket.data.length} bytes</div>`;
                html += `<div class="stream-packet-data">${hexDump}</div>`;
                html += `</div>`;
            }
        });
        
        return html || '<div>이 스트림에는 표시할 데이터가 없습니다.</div>';
    }

    generateRawView(stream) {
        let combinedData = new Uint8Array(0);
        
        stream.packets.forEach(streamPacket => {
            if (streamPacket.data.length > 0) {
                const newData = new Uint8Array(combinedData.length + streamPacket.data.length);
                newData.set(combinedData);
                newData.set(streamPacket.data, combinedData.length);
                combinedData = newData;
            }
        });
        
        const hexDump = this.createHexDump(combinedData);
        return `<div class="stream-packet"><div class="stream-packet-data">${hexDump}</div></div>`;
    }

    bytesToAscii(data) {
        let result = '';
        for (let i = 0; i < data.length; i++) {
            const byte = data[i];
            if (byte >= 32 && byte <= 126) {
                result += String.fromCharCode(byte);
            } else if (byte === 10) {
                result += '\n';
            } else if (byte === 13) {
                result += '\r';
            } else if (byte === 9) {
                result += '\t';
            } else {
                result += '.';
            }
        }
        return result;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    saveCurrentStream() {
        const streamSelect = document.getElementById('streamSelect');
        const streamId = parseInt(streamSelect.value);
        
        if (isNaN(streamId)) {
            alert('저장할 스트림을 선택해주세요.');
            return;
        }

        const stream = this.tcpStreams[streamId];
        const viewMode = document.querySelector('input[name="streamView"]:checked').value;
        
        let content = '';
        let filename = `tcp_stream_${streamId}_${stream.srcIP}_${stream.srcPort}-${stream.destIP}_${stream.destPort}`;
        
        switch (viewMode) {
            case 'ascii':
                content = this.generateAsciiViewForSave(stream);
                filename += '.txt';
                break;
            case 'hex':
                content = this.generateHexViewForSave(stream);
                filename += '.hex';
                break;
            case 'raw':
                content = this.generateRawDataForSave(stream);
                filename += '.bin';
                break;
        }
        
        this.downloadFile(content, filename, viewMode === 'raw' ? 'application/octet-stream' : 'text/plain');
    }

    generateAsciiViewForSave(stream) {
        let content = `TCP Stream ${stream.id}: ${stream.srcIP}:${stream.srcPort} ↔ ${stream.destIP}:${stream.destPort}\n`;
        content += `Packets: ${stream.packets.length}, Bytes: ${stream.totalBytes}\n`;
        content += `Duration: ${((stream.endTime - stream.startTime) / 1000).toFixed(2)}s\n`;
        content += '='.repeat(80) + '\n\n';
        
        stream.packets.forEach((streamPacket, index) => {
            if (streamPacket.data.length > 0) {
                content += `[${streamPacket.direction.toUpperCase()}] Packet #${streamPacket.index + 1} (${streamPacket.packet.timestamp.toISOString()}) - ${streamPacket.data.length} bytes\n`;
                content += this.bytesToAscii(streamPacket.data) + '\n\n';
            }
        });
        
        return content;
    }

    generateHexViewForSave(stream) {
        let content = `TCP Stream ${stream.id}: ${stream.srcIP}:${stream.srcPort} ↔ ${stream.destIP}:${stream.destPort}\n`;
        content += '='.repeat(80) + '\n\n';
        
        stream.packets.forEach((streamPacket, index) => {
            if (streamPacket.data.length > 0) {
                content += `[${streamPacket.direction.toUpperCase()}] Packet #${streamPacket.index + 1}\n`;
                content += this.createHexDump(streamPacket.data) + '\n\n';
            }
        });
        
        return content;
    }

    generateRawDataForSave(stream) {
        let combinedData = new Uint8Array(0);
        
        stream.packets.forEach(streamPacket => {
            if (streamPacket.data.length > 0) {
                const newData = new Uint8Array(combinedData.length + streamPacket.data.length);
                newData.set(combinedData);
                newData.set(streamPacket.data, combinedData.length);
                combinedData = newData;
            }
        });
        
        return combinedData;
    }

    downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = filename;
        link.click();
        URL.revokeObjectURL(link.href);
    }

    formatTimestampWithMicroseconds(timestamp) {
        // JavaScript Date 객체에서 마이크로세컨드 추출
        const milliseconds = timestamp.getMilliseconds();
        
        // YYYY-MM-DD HH:mm:ss.ffffff 형식으로 포맷팅
        const year = timestamp.getFullYear();
        const month = String(timestamp.getMonth() + 1).padStart(2, '0');
        const day = String(timestamp.getDate()).padStart(2, '0');
        const hours = String(timestamp.getHours()).padStart(2, '0');
        const minutes = String(timestamp.getMinutes()).padStart(2, '0');
        const seconds = String(timestamp.getSeconds()).padStart(2, '0');
        
        // 마이크로세컨드는 밀리세컨드에서 추정 (3자리 + 3자리 0으로 패딩)
        const microseconds = String(milliseconds).padStart(3, '0') + '000';
        
        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}.${microseconds}`;
    }

    analyzeHttpSessions() {
        console.log('=== Analyzing HTTP sessions ===');
        this.httpSessions = [];

        console.log(`Total TCP streams: ${this.tcpStreams.length}`);
        
        // 모든 TCP 스트림을 로그로 확인
        this.tcpStreams.forEach((stream, index) => {
            console.log(`Stream ${index}: ${stream.srcIP}:${stream.srcPort} ↔ ${stream.destIP}:${stream.destPort}, packets: ${stream.packets.length}, isHttpStream: ${stream.isHttpStream}`);
        });

        // HTTP 가능성이 있는 TCP 스트림만 분석 (조건 완화)
        const httpStreams = this.tcpStreams.filter(stream => {
            const hasHttpPort = this.isHttpPort(stream.srcPort) || this.isHttpPort(stream.destPort);
            const isMarkedHttp = stream.isHttpStream;
            const hasDataPackets = stream.packets.some(p => p.data && p.data.length > 0);
            const hasLargePackets = stream.hasLargePackets || stream.packets.some(p => p.packetSize > 100);
            
            console.log(`Stream ${stream.id} - HTTP port: ${hasHttpPort}, marked HTTP: ${isMarkedHttp}, has data: ${hasDataPackets}, large packets: ${hasLargePackets}`);
            
            return hasHttpPort || isMarkedHttp || hasDataPackets || hasLargePackets;
        });

        console.log(`Analyzing ${httpStreams.length} potential HTTP streams out of ${this.tcpStreams.length} TCP streams`);

        httpStreams.forEach(stream => {
            console.log(`=== Checking stream ${stream.id}: ${stream.srcIP}:${stream.srcPort} ↔ ${stream.destIP}:${stream.destPort} ===`);
            
            const httpSession = this.extractHttpFromTcpStream(stream);
            if (httpSession) {
                this.httpSessions.push(httpSession);
                console.log(`✓ Found HTTP session in stream ${stream.id} with ${httpSession.messages.length} messages`);
            } else {
                console.log(`✗ No HTTP session found in stream ${stream.id}`);
            }
        });

        console.log(`=== Final result: Found ${this.httpSessions.length} HTTP sessions ===`);
    }

    extractHttpFromTcpStream(tcpStream) {
        const httpMessages = [];
        let currentRequest = null;
        let currentResponse = null;
        let streamData = [];

        // 모든 패킷 데이터를 순서대로 연결
        tcpStream.packets.forEach(streamPacket => {
            if (streamPacket.data.length > 0) {
                streamData.push({
                    data: streamPacket.data,
                    direction: streamPacket.direction,
                    packet: streamPacket.packet,
                    index: streamPacket.index
                });
            }
        });

        console.log(`Stream ${tcpStream.id} has ${streamData.length} packets with data`);

        // 각 패킷의 데이터를 ASCII로 변환하여 HTTP 메시지 찾기
        streamData.forEach(item => {
            const ascii = this.bytesToAscii(item.data);
            
            if (ascii.length < 10) return; // 너무 짧은 데이터는 스킵
            
            console.log(`Packet data (${item.direction}): ${ascii.substring(0, 100)}...`);
            
            // HTTP 요청 감지
            if (this.isHttpRequest(ascii)) {
                console.log('Found HTTP request');
                // 이전 요청이 있다면 저장
                if (currentRequest) {
                    httpMessages.push(currentRequest);
                }
                currentRequest = this.parseHttpRequest(ascii, item);
            }
            // HTTP 응답 감지
            else if (this.isHttpResponse(ascii)) {
                console.log('Found HTTP response');
                currentResponse = this.parseHttpResponse(ascii, item);
                
                // 요청-응답 쌍이 완성되면 저장
                if (currentRequest && currentResponse) {
                    httpMessages.push({
                        type: 'request-response-pair',
                        request: currentRequest,
                        response: currentResponse,
                        timestamp: currentRequest.timestamp
                    });
                    currentRequest = null;
                    currentResponse = null;
                } else if (currentResponse) {
                    // 응답만 있는 경우도 저장
                    httpMessages.push(currentResponse);
                    currentResponse = null;
                }
            }
            // 기존 메시지에 데이터 추가 (멀티패킷 메시지)
            else if (currentRequest && ascii.trim()) {
                currentRequest.body += ascii;
            } else if (currentResponse && ascii.trim()) {
                currentResponse.body += ascii;
            }
        });

        // 마지막 요청이나 응답이 있다면 저장
        if (currentRequest) {
            httpMessages.push(currentRequest);
        }
        if (currentResponse) {
            httpMessages.push(currentResponse);
        }

        console.log(`Stream ${tcpStream.id} yielded ${httpMessages.length} HTTP messages`);

        if (httpMessages.length === 0) return null;

        return {
            id: this.httpSessions.length,
            tcpStreamId: tcpStream.id,
            host: this.extractHostFromStream(tcpStream),
            messages: httpMessages,
            totalRequests: httpMessages.filter(m => m.type === 'request' || m.type === 'request-response-pair').length,
            startTime: tcpStream.startTime,
            endTime: tcpStream.endTime
        };
    }

    isHttpRequest(data) {
        if (!data || data.length < 4) return false;
        const methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'TRACE ', 'CONNECT '];
        const result = methods.some(method => data.startsWith(method));
        if (result) {
            console.log(`Found HTTP request: ${data.substring(0, 50)}...`);
        }
        return result;
    }

    isHttpResponse(data) {
        if (!data || data.length < 8) return false;
        const result = /^HTTP\/\d\.\d \d{3}/.test(data);
        if (result) {
            console.log(`Found HTTP response: ${data.substring(0, 50)}...`);
        }
        return result;
    }

    parseHttpRequest(data, streamPacket) {
        const lines = data.split('\n');
        const requestLine = lines[0].trim();
        const parts = requestLine.split(' ');
        
        const headers = {};
        let bodyStartIndex = -1;
        
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (line === '') {
                bodyStartIndex = i + 1;
                break;
            }
            
            const colonIndex = line.indexOf(':');
            if (colonIndex > -1) {
                const key = line.substring(0, colonIndex).trim();
                const value = line.substring(colonIndex + 1).trim();
                headers[key] = value;
            }
        }
        
        const body = bodyStartIndex > -1 ? lines.slice(bodyStartIndex).join('\n') : '';
        
        return {
            type: 'request',
            method: parts[0] || '',
            url: parts[1] || '',
            version: parts[2] || '',
            headers,
            body,
            timestamp: streamPacket.packet.timestamp,
            packetIndex: streamPacket.index,
            rawData: data
        };
    }

    parseHttpResponse(data, streamPacket) {
        const lines = data.split('\n');
        const statusLine = lines[0].trim();
        const parts = statusLine.split(' ');
        
        const headers = {};
        let bodyStartIndex = -1;
        
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (line === '') {
                bodyStartIndex = i + 1;
                break;
            }
            
            const colonIndex = line.indexOf(':');
            if (colonIndex > -1) {
                const key = line.substring(0, colonIndex).trim();
                const value = line.substring(colonIndex + 1).trim();
                headers[key] = value;
            }
        }
        
        const body = bodyStartIndex > -1 ? lines.slice(bodyStartIndex).join('\n') : '';
        
        return {
            type: 'response',
            version: parts[0] || '',
            statusCode: parseInt(parts[1]) || 0,
            statusText: parts.slice(2).join(' ') || '',
            headers,
            body,
            timestamp: streamPacket.packet.timestamp,
            packetIndex: streamPacket.index,
            rawData: data
        };
    }

    extractHostFromStream(tcpStream) {
        return `${tcpStream.srcIP}:${tcpStream.srcPort} ↔ ${tcpStream.destIP}:${tcpStream.destPort}`;
    }

    openHttpAnalysis() {
        console.log(`HTTP sessions count: ${this.httpSessions.length}`);
        console.log(`TCP streams count: ${this.tcpStreams.length}`);
        
        // HTTP 세션이 없다면 다시 분석 시도
        if (this.httpSessions.length === 0) {
            console.log('No HTTP sessions found, re-analyzing...');
            this.analyzeHttpSessions();
        }
        
        if (this.httpSessions.length === 0) {
            console.log('Still no HTTP sessions after re-analysis');
            alert('HTTP 세션이 발견되지 않았습니다. HTTP 트래픽이 포함된 캡처 파일을 분석해주세요.');
            return;
        }

        // HTTP 세션 목록 업데이트
        const httpSessionSelect = document.getElementById('httpSessionSelect');
        httpSessionSelect.innerHTML = '<option value="">세션을 선택하세요</option>';
        
        this.httpSessions.forEach(session => {
            const option = document.createElement('option');
            option.value = session.id;
            option.textContent = `Session ${session.id}: ${session.host} (${session.totalRequests} requests)`;
            httpSessionSelect.appendChild(option);
        });

        // 모달 표시
        document.getElementById('httpAnalysisModal').style.display = 'flex';
    }

    closeHttpAnalysisModal() {
        document.getElementById('httpAnalysisModal').style.display = 'none';
    }

    handleHttpSessionSelect() {
        const httpSessionSelect = document.getElementById('httpSessionSelect');
        const sessionId = parseInt(httpSessionSelect.value);
        
        if (isNaN(sessionId)) {
            document.getElementById('httpData').textContent = 'HTTP 세션을 선택하면 여기에 데이터가 표시됩니다.';
            document.getElementById('httpSessionInfo').textContent = '';
            return;
        }

        const session = this.httpSessions[sessionId];
        if (session) {
            const duration = ((session.endTime - session.startTime) / 1000).toFixed(2);
            const info = `${session.messages.length} messages, ${session.totalRequests} requests, ${duration}s duration`;
            document.getElementById('httpSessionInfo').textContent = info;
            this.updateHttpView();
        }
    }

    updateHttpView() {
        const httpSessionSelect = document.getElementById('httpSessionSelect');
        const sessionId = parseInt(httpSessionSelect.value);
        
        if (isNaN(sessionId)) return;
        
        const session = this.httpSessions[sessionId];
        if (!session) return;

        const viewMode = document.querySelector('input[name="httpView"]:checked').value;
        const httpData = document.getElementById('httpData');
        
        let content = '';
        
        switch (viewMode) {
            case 'summary':
                content = this.generateHttpSummaryView(session);
                break;
            case 'headers':
                content = this.generateHttpHeadersView(session);
                break;
            case 'body':
                content = this.generateHttpBodyView(session);
                break;
            case 'raw':
                content = this.generateHttpRawView(session);
                break;
        }
        
        httpData.innerHTML = content;
    }

    generateHttpSummaryView(session) {
        let html = `<h4>HTTP 세션 요약: ${session.host}</h4>`;
        
        html += `<table class="http-summary-table">
            <thead>
                <tr>
                    <th>시간</th>
                    <th>타입</th>
                    <th>메서드/상태</th>
                    <th>URL/메시지</th>
                    <th>Content-Type</th>
                </tr>
            </thead>
            <tbody>`;
        
        session.messages.forEach(message => {
            if (message.type === 'request-response-pair') {
                const req = message.request;
                const res = message.response;
                
                html += `<tr>
                    <td>${req.timestamp.toLocaleTimeString()}</td>
                    <td>REQUEST</td>
                    <td><span class="http-method">${req.method}</span></td>
                    <td>${req.url}</td>
                    <td>${req.headers['Content-Type'] || '-'}</td>
                </tr>`;
                
                const statusClass = this.getStatusClass(res.statusCode);
                html += `<tr>
                    <td>${res.timestamp.toLocaleTimeString()}</td>
                    <td>RESPONSE</td>
                    <td><span class="http-status-code ${statusClass}">${res.statusCode} ${res.statusText}</span></td>
                    <td>-</td>
                    <td>${res.headers['Content-Type'] || '-'}</td>
                </tr>`;
            } else if (message.type === 'request') {
                html += `<tr>
                    <td>${message.timestamp.toLocaleTimeString()}</td>
                    <td>REQUEST</td>
                    <td><span class="http-method">${message.method}</span></td>
                    <td>${message.url}</td>
                    <td>${message.headers['Content-Type'] || '-'}</td>
                </tr>`;
            }
        });
        
        html += `</tbody></table>`;
        return html;
    }

    generateHttpHeadersView(session) {
        let html = `<h4>HTTP 헤더 분석: ${session.host}</h4>`;
        
        session.messages.forEach((message, index) => {
            if (message.type === 'request-response-pair') {
                const req = message.request;
                const res = message.response;
                
                html += `<div class="http-request">
                    <div class="http-message-header">요청 #${index + 1}: ${req.method} ${req.url}</div>
                    <div class="http-headers">`;
                
                Object.entries(req.headers).forEach(([key, value]) => {
                    html += `<div><strong>${this.escapeHtml(key)}:</strong> ${this.escapeHtml(value)}</div>`;
                });
                
                html += `</div></div>`;
                
                html += `<div class="http-response">
                    <div class="http-message-header">응답 #${index + 1}: ${res.statusCode} ${res.statusText}</div>
                    <div class="http-headers">`;
                
                Object.entries(res.headers).forEach(([key, value]) => {
                    html += `<div><strong>${this.escapeHtml(key)}:</strong> ${this.escapeHtml(value)}</div>`;
                });
                
                html += `</div></div>`;
            } else if (message.type === 'request') {
                html += `<div class="http-request">
                    <div class="http-message-header">요청 #${index + 1}: ${message.method} ${message.url}</div>
                    <div class="http-headers">`;
                
                Object.entries(message.headers).forEach(([key, value]) => {
                    html += `<div><strong>${this.escapeHtml(key)}:</strong> ${this.escapeHtml(value)}</div>`;
                });
                
                html += `</div></div>`;
            }
        });
        
        return html;
    }

    generateHttpBodyView(session) {
        let html = `<h4>HTTP 바디 내용: ${session.host}</h4>`;
        
        session.messages.forEach((message, index) => {
            if (message.type === 'request-response-pair') {
                const req = message.request;
                const res = message.response;
                
                if (req.body.trim()) {
                    html += `<div class="http-request">
                        <div class="http-message-header">요청 바디 #${index + 1}</div>
                        <div class="http-body">${this.escapeHtml(req.body)}</div>
                    </div>`;
                }
                
                if (res.body.trim()) {
                    html += `<div class="http-response">
                        <div class="http-message-header">응답 바디 #${index + 1}</div>
                        <div class="http-body">${this.escapeHtml(res.body)}</div>
                    </div>`;
                }
            } else if (message.type === 'request' && message.body.trim()) {
                html += `<div class="http-request">
                    <div class="http-message-header">요청 바디 #${index + 1}</div>
                    <div class="http-body">${this.escapeHtml(message.body)}</div>
                </div>`;
            }
        });
        
        return html || '<div>이 세션에는 바디 데이터가 없습니다.</div>';
    }

    generateHttpRawView(session) {
        let html = `<h4>HTTP 전체 데이터: ${session.host}</h4>`;
        
        session.messages.forEach((message, index) => {
            if (message.type === 'request-response-pair') {
                html += `<div class="http-request">
                    <div class="http-message-header">요청 #${index + 1} (패킷 #${message.request.packetIndex + 1})</div>
                    <div class="http-message-content">${this.escapeHtml(message.request.rawData)}</div>
                </div>`;
                
                html += `<div class="http-response">
                    <div class="http-message-header">응답 #${index + 1} (패킷 #${message.response.packetIndex + 1})</div>
                    <div class="http-message-content">${this.escapeHtml(message.response.rawData)}</div>
                </div>`;
            } else if (message.type === 'request') {
                html += `<div class="http-request">
                    <div class="http-message-header">요청 #${index + 1} (패킷 #${message.packetIndex + 1})</div>
                    <div class="http-message-content">${this.escapeHtml(message.rawData)}</div>
                </div>`;
            }
        });
        
        return html;
    }

    getStatusClass(statusCode) {
        if (statusCode >= 200 && statusCode < 300) return 'http-status-200';
        if (statusCode >= 300 && statusCode < 400) return 'http-status-300';
        if (statusCode >= 400 && statusCode < 500) return 'http-status-400';
        if (statusCode >= 500) return 'http-status-500';
        return '';
    }

    saveCurrentHttpSession() {
        const httpSessionSelect = document.getElementById('httpSessionSelect');
        const sessionId = parseInt(httpSessionSelect.value);
        
        if (isNaN(sessionId)) {
            alert('저장할 HTTP 세션을 선택해주세요.');
            return;
        }

        const session = this.httpSessions[sessionId];
        const viewMode = document.querySelector('input[name="httpView"]:checked').value;
        
        let content = '';
        let filename = `http_session_${sessionId}_${session.host.replace(/[:\s↔]/g, '_')}`;
        
        switch (viewMode) {
            case 'summary':
                content = this.generateHttpSummaryForSave(session);
                filename += '_summary.txt';
                break;
            case 'headers':
                content = this.generateHttpHeadersForSave(session);
                filename += '_headers.txt';
                break;
            case 'body':
                content = this.generateHttpBodyForSave(session);
                filename += '_body.txt';
                break;
            case 'raw':
                content = this.generateHttpRawForSave(session);
                filename += '_raw.txt';
                break;
        }
        
        this.downloadFile(content, filename, 'text/plain');
    }

    generateHttpSummaryForSave(session) {
        let content = `HTTP 세션 요약 보고서\n`;
        content += `호스트: ${session.host}\n`;
        content += `메시지 수: ${session.messages.length}\n`;
        content += `요청 수: ${session.totalRequests}\n`;
        content += `시작 시간: ${session.startTime.toLocaleString()}\n`;
        content += `종료 시간: ${session.endTime.toLocaleString()}\n`;
        content += `지속 시간: ${((session.endTime - session.startTime) / 1000).toFixed(2)}초\n`;
        content += '='.repeat(80) + '\n\n';
        
        session.messages.forEach((message, index) => {
            if (message.type === 'request-response-pair') {
                const req = message.request;
                const res = message.response;
                
                content += `[${index + 1}] 요청-응답 쌍\n`;
                content += `요청: ${req.method} ${req.url}\n`;
                content += `응답: ${res.statusCode} ${res.statusText}\n`;
                content += `시간: ${req.timestamp.toLocaleString()}\n\n`;
            } else if (message.type === 'request') {
                content += `[${index + 1}] 요청\n`;
                content += `메서드: ${message.method} ${message.url}\n`;
                content += `시간: ${message.timestamp.toLocaleString()}\n\n`;
            }
        });
        
        return content;
    }

    generateHttpHeadersForSave(session) {
        let content = `HTTP 헤더 분석 보고서\n`;
        content += `호스트: ${session.host}\n`;
        content += '='.repeat(80) + '\n\n';
        
        session.messages.forEach((message, index) => {
            if (message.type === 'request-response-pair') {
                const req = message.request;
                const res = message.response;
                
                content += `[요청 #${index + 1}] ${req.method} ${req.url}\n`;
                Object.entries(req.headers).forEach(([key, value]) => {
                    content += `${key}: ${value}\n`;
                });
                content += '\n';
                
                content += `[응답 #${index + 1}] ${res.statusCode} ${res.statusText}\n`;
                Object.entries(res.headers).forEach(([key, value]) => {
                    content += `${key}: ${value}\n`;
                });
                content += '\n';
            } else if (message.type === 'request') {
                content += `[요청 #${index + 1}] ${message.method} ${message.url}\n`;
                Object.entries(message.headers).forEach(([key, value]) => {
                    content += `${key}: ${value}\n`;
                });
                content += '\n';
            }
        });
        
        return content;
    }

    generateHttpBodyForSave(session) {
        let content = `HTTP 바디 데이터\n`;
        content += `호스트: ${session.host}\n`;
        content += '='.repeat(80) + '\n\n';
        
        session.messages.forEach((message, index) => {
            if (message.type === 'request-response-pair') {
                const req = message.request;
                const res = message.response;
                
                if (req.body.trim()) {
                    content += `[요청 바디 #${index + 1}]\n`;
                    content += req.body + '\n\n';
                }
                
                if (res.body.trim()) {
                    content += `[응답 바디 #${index + 1}]\n`;
                    content += res.body + '\n\n';
                }
            } else if (message.type === 'request' && message.body.trim()) {
                content += `[요청 바디 #${index + 1}]\n`;
                content += message.body + '\n\n';
            }
        });
        
        return content;
    }

    generateHttpRawForSave(session) {
        let content = `HTTP 전체 데이터\n`;
        content += `호스트: ${session.host}\n`;
        content += '='.repeat(80) + '\n\n';
        
        session.messages.forEach((message, index) => {
            if (message.type === 'request-response-pair') {
                content += `[요청 #${index + 1}]\n`;
                content += message.request.rawData + '\n\n';
                
                content += `[응답 #${index + 1}]\n`;
                content += message.response.rawData + '\n\n';
            } else if (message.type === 'request') {
                content += `[요청 #${index + 1}]\n`;
                content += message.rawData + '\n\n';
            }
        });
        
        return content;
    }
}

let analyzer;

document.addEventListener('DOMContentLoaded', () => {
    analyzer = new PcapAnalyzer();
});