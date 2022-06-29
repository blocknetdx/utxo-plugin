import struct
import lib.tx as lib_tx
import lib.tx_dash as lib_tx_dash
import lib.coins as BlockProc
import electrumx.lib.util as util
import electrumx.server.daemon as daemon
import electrumx.server.block_processor as block_proc
from electrumx.lib.coins import AuxPowMixin, ScryptMixin, CoinError, Coin as CoinBase
from electrumx.lib.hash import hash_to_hex_str
from server.daemon import SyscoinDaemon
from server.session import (ElectrumX, BitcoinSegwitElectrumX, DashElectrumX,
                            SmartCashElectrumX, AuxPoWElectrumX, SyscoinElectrumX)


class Coin(CoinBase):
    DESERIALIZER = lib_tx.Deserializer
    DAEMON = daemon.Daemon
    BLOCK_PROCESSOR = BlockProc.BlockProcessor
    SESSIONCLS = ElectrumX
    REORG_LIMIT = 2000


class AuxPowHelper(AuxPowMixin):
    SESSIONCLS = AuxPoWElectrumX
    DESERIALIZER = lib_tx.DeserializerAuxPow


class BlocknetMixin(object):
    NET = "mainnet"
    DAEMON = daemon.LegacyRPCDaemon
    DESERIALIZER = lib_tx.DeserializerSegWit
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("1A")
    P2SH_VERBYTES = [bytes.fromhex("1C")]
    WIF_BYTE = bytes.fromhex("9A")
    GENESIS_HASH = ('00000eb7919102da5a07dc90905651664e6ebf0811c28f06573b9a0fd84ab7b8')
    RPC_PORT = 41414
    #  HDR_V4_HEIGHT = 1
    #  HDR_V4_SIZE = 112
    BASIC_HEADER_SIZE = 80
    TX_COUNT = 204387
    TX_COUNT_HEIGHT = 101910
    TX_PER_BLOCK = 2
    #  HDR_V4_START_OFFSET = HDR_V4_HEIGHT * BASIC_HEADER_SIZE


class Blocknet(BlocknetMixin, Coin):
    NAME = "Blocknet"
    SHORTNAME = "BLOCK"

    @classmethod
    def header_hash(cls, header):
        version, = util.unpack_le_uint32_from(header)

        if len(header) != 80 and version >= 3:
            return super().header_hash(header[:cls.BASIC_HEADER_SIZE])
        else:
            import quark_hash
            return quark_hash.getPoWHash(header[:cls.BASIC_HEADER_SIZE])


class BlocknetTestnetMixin(object):
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("3A8061A0")
    XPRV_VERBYTES = bytes.fromhex("3A805837")
    P2PKH_VERBYTE = bytes.fromhex("8B")
    P2SH_VERBYTES = [bytes.fromhex("13")]
    WIF_BYTE = bytes.fromhex("EF")
    GENESIS_HASH = ('0fd62ae4f74c7ee0c11ef60fc5a2e69a'
                    '5c02eaee2e77b21c3db70934b5a5c8b9')
    RPC_PORT = 41419
    #  HDR_V4_HEIGHT = 1
    #  HDR_V4_SIZE = 112
    TX_COUNT = 204387
    TX_COUNT_HEIGHT = 101910
    TX_PER_BLOCK = 2
    #  HDR_V4_START_OFFSET = HDR_V4_HEIGHT * BASIC_HEADER_SIZE


class BlocknetTestnet(BlocknetTestnetMixin, Coin):
    NAME = "BlocknetTestnet"
    SHORTNAME = "TBLOCK"

    @classmethod
    def header_hash(cls, header):
        version, = util.unpack_le_uint32_from(header)
        if version >= 4:
            return super().header_hash(header)
        else:
            import quark_hash
            return quark_hash.getPoWHash(header)


class Syscoin(AuxPowHelper, Coin):
    NAME = "Syscoin"
    SHORTNAME = "SYS"
    NET = "mainnet"

    P2PKH_VERBYTE = bytes.fromhex("3f")
    P2SH_VERBYTES = bytes.fromhex("05")
    WIF_BYTE = bytes.fromhex("80")

    GENESIS_HASH = '0000022642db0346b6e01c2a397471f4f12e65d4f4251ec96c1f85367a61a7ab'
    TX_COUNT = 17036
    TX_COUNT_HEIGHT = 16485
    TX_PER_BLOCK = 5
    RPC_PORT = 8368

    DEFAULT_COST_SOFT_LIMIT = 0
    DEFAULT_COST_HARD_LIMIT = 0
    DEFAULT_BANDWIDTH_UNIT_COST = 5000
    DEFAULT_INITIAL_CONCURRENT = 10

    # auxpow header params are not static
    STATIC_BLOCK_HEADERS = False
    BASIC_HEADER_SIZE = 80

    # AuxPoW headers are significantly larger, so the DEFAULT_MAX_SEND from
    # Bitcoin is insufficient.  In Syscoin mainnet, 5 MB wasn't enough to
    # sync, while 10 MB worked fine.
    DEFAULT_MAX_SEND = 10000000

    DAEMON = SyscoinDaemon
    SESSIONCLS = SyscoinElectrumX
    DESERIALIZER = lib_tx.DeserializerAuxPowSegWit


class BitcoinMixin(object):
    SHORTNAME = "BTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("00")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('000000000019d6689c085ae165831e93'
                    '4ff763ae46a2a6c172b3f1b60a8ce26f')
    RPC_PORT = 8332


class Bitcoin(BitcoinMixin, Coin):
    NAME = "Bitcoin"
    DESERIALIZER = lib_tx.Deserializer

    TX_COUNT = 217380620
    TX_COUNT_HEIGHT = 464000
    TX_PER_BLOCK = 1800


class BitcoinSegwit(BitcoinMixin, Coin):
    NAME = "BitcoinSegwit"
    DESERIALIZER = lib_tx.DeserializerSegWit
    SESSIONCLS = BitcoinSegwitElectrumX
    MEMPOOL_HISTOGRAM_REFRESH_SECS = 120
    TX_COUNT = 318337769
    TX_COUNT_HEIGHT = 524213
    TX_PER_BLOCK = 1400
    BLACKLIST_URL = 'https://electrum.org/blacklist.json'
    PEERS = [
        'btc.smsys.me s995',
        'E-X.not.fyi s t',
        'elec.luggs.co s443',
        'electrum.vom-stausee.de s t',
        'electrum.hsmiths.com s t',
        'helicarrier.bauerj.eu s t',
        'hsmiths4fyqlw5xw.onion s t',
        'luggscoqbymhvnkp.onion t80',
        'ozahtqwp25chjdjd.onion s t',
        'node.arihanc.com s t',
        'arihancckjge66iv.onion s t',
    ]

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, client_ver):
        if client_ver < (3, 3, 3):
            return ('<br/><br/>'
                    'Your transaction was successfully broadcast.<br/><br/>'
                    'However, you are using a VULNERABLE version of Electrum.<br/>'
                    'Download the new version from the usual place:<br/>'
                    'https://electrum.org/'
                    '<br/><br/>')
        return False


class Bitcore(BitcoinMixin, Coin):
    NAME = "Bitcore"
    SHORTNAME = "BTX"
    P2PKH_VERBYTE = bytes.fromhex("03")
    P2SH_VERBYTES = [bytes.fromhex("7D")]
    WIF_BYTE = bytes.fromhex("80")
    DESERIALIZER = lib_tx.DeserializerSegWit
    GENESIS_HASH = ('604148281e5c4b7f2487e5d03cd60d8e'
                    '6f69411d613f6448034508cea52e9574')
    TX_COUNT = 126979
    TX_COUNT_HEIGHT = 126946
    TX_PER_BLOCK = 2
    RPC_PORT = 8556


class Litecoin(Coin):
    NAME = "Litecoin"
    SHORTNAME = "LTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("30")
    P2SH_VERBYTES = [bytes.fromhex("32"), bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('12a765e31ffd4059bada1e25190f6e98'
                    'c99d9714d334efa41a195a7e7e04bfe2')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 8908766
    TX_COUNT_HEIGHT = 1105256
    TX_PER_BLOCK = 10
    RPC_PORT = 9332


class DigiByte(Coin):
    NAME = "DigiByte"
    SHORTNAME = "DGB"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1E")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('7497ea1b465eb39f1c8f507bc877078f'
                    'e016d6fcb6dfad3a64c98dcc6e1e8496')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1046018
    TX_COUNT_HEIGHT = 1435000
    TX_PER_BLOCK = 1000
    RPC_PORT = 12022


class Dogecoin(AuxPowHelper, Coin):
    NAME = "Dogecoin"
    SHORTNAME = "DOGE"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("02facafd")
    XPRV_VERBYTES = bytes.fromhex("02fac398")
    P2PKH_VERBYTE = bytes.fromhex("1e")
    P2SH_VERBYTES = [bytes.fromhex("16")]
    WIF_BYTE = bytes.fromhex("9e")
    GENESIS_HASH = ('1a91e3dace36e2be3bf030a65679fe82'
                    '1aa1d6ef92e7c9902eb318182c355691')
    TX_COUNT = 27583427
    TX_COUNT_HEIGHT = 1604979
    TX_PER_BLOCK = 20
    PEERS = []


class Dash(Coin):
    NAME = "Dash"
    SHORTNAME = "DASH"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("02fe52cc")
    XPRV_VERBYTES = bytes.fromhex("02fe52f8")
    GENESIS_HASH = ('00000ffd590b1485b3caadc19b22e637'
                    '9c733355108f107a430458cdf3407ab6')
    P2PKH_VERBYTE = bytes.fromhex("4c")
    P2SH_VERBYTES = [bytes.fromhex("10")]
    WIF_BYTE = bytes.fromhex("cc")
    TX_COUNT_HEIGHT = 569399
    TX_COUNT = 2157510
    TX_PER_BLOCK = 4
    RPC_PORT = 9998
    PEERS = []
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon
    DESERIALIZER = lib_tx_dash.DeserializerDash

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x11_hash
        return x11_hash.getPoWHash(header)


class Polis(Coin):
    NAME = "Polis"
    SHORTNAME = "POLIS"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("03E25D7E")
    XPRV_VERBYTES = bytes.fromhex("03E25945")
    GENESIS_HASH = ('000009701eb781a8113b1af1d814e2f0'
                    '60f6408a2c990db291bc5108a1345c1e')
    P2PKH_VERBYTE = bytes.fromhex("37")
    P2SH_VERBYTES = [bytes.fromhex("38")]
    WIF_BYTE = bytes.fromhex("3c")
    TX_COUNT_HEIGHT = 280600
    TX_COUNT = 635415
    TX_PER_BLOCK = 4
    RPC_PORT = 24127
    PEERS = [
        'electrum.polispay.com'
    ]
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon
    DESERIALIZER = lib_tx_dash.DeserializerDash

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x11_hash
        return x11_hash.getPoWHash(header)


class Phore(Coin):
    NAME = "Phore"
    SHORTNAME = "PHR"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("022D2533")
    XPRV_VERBYTES = bytes.fromhex("0221312B")
    GENESIS_HASH = ('2b1a0f66712aad59ad283662d5b91941'
                    '5a25921ce89511d73019107e380485bf')
    P2PKH_VERBYTE = bytes.fromhex("37")
    P2SH_VERBYTES = [bytes.fromhex("0d")]
    WIF_BYTE = bytes.fromhex("d4")
    BASIC_HEADER_SIZE = 80
    HDR_V4_SIZE = 112
    HDR_V4_HEIGHT = 89993
    HDR_V4_START_OFFSET = HDR_V4_HEIGHT * BASIC_HEADER_SIZE
    TX_COUNT_HEIGHT = 280600
    TX_COUNT = 635415
    TX_PER_BLOCK = 4
    RPC_PORT = 11771
    PEERS = []
    DESERIALIZER = lib_tx.Deserializer

    @classmethod
    def static_header_offset(cls, height):
        assert cls.STATIC_BLOCK_HEADERS
        if height >= cls.HDR_V4_HEIGHT:
            relative_v4_offset = (height - cls.HDR_V4_HEIGHT) * cls.HDR_V4_SIZE
            return cls.HDR_V4_START_OFFSET + relative_v4_offset
        else:
            return height * cls.BASIC_HEADER_SIZE

    @classmethod
    def header_hash(cls, header):
        version, = struct.unpack('<I', header[:4])
        if version >= 4:
            return super().header_hash(header)
        else:
            import quark_hash
            return quark_hash.getPoWHash(header)


class Alqo(Coin):
    NAME = "Alqo"
    SHORTNAME = "XLQ"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("022D2533")
    XPRV_VERBYTES = bytes.fromhex("0221312B")
    GENESIS_HASH = ('000040f1123764b16ac29f9c6c994e5b'
                    'eeacaf21f751062f5ab2c651351e0db1')
    P2PKH_VERBYTE = bytes.fromhex("53")
    P2SH_VERBYTES = [bytes.fromhex("5A")]
    WIF_BYTE = bytes.fromhex("D3")
    TX_COUNT_HEIGHT = 280600
    TX_COUNT = 635415
    TX_PER_BLOCK = 4
    RPC_PORT = 11771
    PEERS = []
    DESERIALIZER = lib_tx.Deserializer
    BASIC_HEADER_SIZE = 80
    # STATIC_BLOCK_HEADERS = True
    # ZEROCOIN_HEADER = 80
    # ZEROCOIN_START_HEIGHT = 33554432
    ZEROCOIN_BLOCK_VERSION = 4
    # ZEROCOIN_START_OFFSET = ZEROCOIN_START_HEIGHT * (BASIC_HEADER_SIZE - ZEROCOIN_HEADER)

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        version, = struct.unpack('<I', header[:4])

        if version == 1 or version >= cls.ZEROCOIN_BLOCK_VERSION:
            return super().header_hash(header[:cls.BASIC_HEADER_SIZE])
        else:
            import quark_hash
            return quark_hash.getPoWHash(header[:cls.BASIC_HEADER_SIZE])

    @classmethod
    def genesis_block(cls, block):
        '''Check the Genesis block is the right one for this coin.
        Return the block less its unspendable coinbase.
        '''
        header = cls.block_header(block, 0)
        header_hex_hash = hash_to_hex_str(super().header_hash(header[:cls.BASIC_HEADER_SIZE]))
        if header_hex_hash != cls.GENESIS_HASH:
            raise CoinError('genesis block has hash {} expected {}'
                            .format(header_hex_hash, cls.GENESIS_HASH))
        return header + bytes(1)


class Bitbay(ScryptMixin, Coin):
    NAME = "Bitbay"
    DAEMON = daemon.LegacyRPCDaemon
    SHORTNAME = "BAY"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = [bytes.fromhex("55")]
    WIF_BYTE = bytes.fromhex("99")
    GENESIS_HASH = ('0000075685d3be1f253ce777174b1594'
                    '354e79954d2a32a6f77fe9cba00e6467')
    TX_COUNT = 4594999
    TX_COUNT_HEIGHT = 1667070
    TX_PER_BLOCK = 3
    RPC_PORT = 19914


class Ravencoin(Coin):
    NAME = "Ravencoin"
    SHORTNAME = "RVN"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("3C")
    P2SH_VERBYTES = [bytes.fromhex("7A")]
    GENESIS_HASH = ('0000006b444bc2f2ffe627be9d9e7e7a'
                    '0730000870ef6eb6da46c8eae389df90')
    DESERIALIZER = lib_tx.DeserializerSegWit
    X16RV2_ACTIVATION_TIME = 1569945600  # algo switch to x16rv2 at this timestamp
    TX_COUNT = 5626682
    TX_COUNT_HEIGHT = 887000
    TX_PER_BLOCK = 6
    RPC_PORT = 8766
    PEERS = [
    ]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        timestamp = util.unpack_le_uint32_from(header, 68)[0]
        if timestamp >= cls.X16RV2_ACTIVATION_TIME:
            import x16rv2_hash
            return x16rv2_hash.getPoWHash(header)
        else:
            import x16r_hash
            return x16r_hash.getPoWHash(header)


class Pivx(Coin):
    NAME = "PIVX"
    SHORTNAME = "PIVX"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("022D2533")
    XPRV_VERBYTES = bytes.fromhex("0221312B")
    GENESIS_HASH = ('0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818')
    P2PKH_VERBYTE = bytes.fromhex("1e")
    P2SH_VERBYTE = bytes.fromhex("0d")
    WIF_BYTE = bytes.fromhex("d4")
    TX_COUNT_HEIGHT = 569399
    TX_COUNT = 2157510
    TX_PER_BLOCK = 1
    STATIC_BLOCK_HEADERS = False
    RPC_PORT = 51470
    BASIC_HEADER_SIZE = 80
    ZEROCOIN_HEADER = 112
    ZEROCOIN_START_HEIGHT = 863787
    ZEROCOIN_V7_START_HEIGHT = 2153200
    ZEROCOIN_BLOCK_VERSION = 4
    ZEROCOIN_START_OFFSET = ZEROCOIN_START_HEIGHT * (BASIC_HEADER_SIZE - ZEROCOIN_HEADER)

    @classmethod
    def static_header_offset(cls, height):
        '''Given a header height return its offset in the headers file.

        If header sizes change at some point, this is the only code
        that needs updating.'''
        assert cls.STATIC_BLOCK_HEADERS
        if height >= cls.ZEROCOIN_START_HEIGHT:
            return cls.ZEROCOIN_START_OFFSET + height * cls.ZEROCOIN_HEADER
        else:
            return height * cls.BASIC_HEADER_SIZE

    @classmethod
    def static_header_len(cls, height):
        '''Given a header height return its length.'''
        if cls.ZEROCOIN_START_HEIGHT <= height < cls.ZEROCOIN_V7_START_HEIGHT:
            return cls.ZEROCOIN_HEADER
        else:
            return cls.BASIC_HEADER_SIZE

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        version, = struct.unpack('<I', header[:4])
        if version >= cls.ZEROCOIN_BLOCK_VERSION:
            return super().header_hash(header)
        else:
            import quark_hash
            return quark_hash.getPoWHash(header)


class Trezarcoin(Coin):
    NAME = "Trezarcoin"
    SHORTNAME = "TZC"
    NET = "mainnet"
    VALUE_PER_COIN = 1000000
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("42")
    P2SH_VERBYTES = [bytes.fromhex("08")]
    WIF_BYTE = bytes.fromhex("c2")
    GENESIS_HASH = ('24502ba55d673d2ee9170d83dae2d1ad'
                    'b3bfb4718e4f200db9951382cc4f6ee6')
    DESERIALIZER = lib_tx.DeserializerTrezarcoin
    HEADER_HASH = lib_tx.DeserializerTrezarcoin.blake2s
    HEADER_HASH_GEN = lib_tx.DeserializerTrezarcoin.blake2s_gen
    BASIC_HEADER_SIZE = 80
    TX_COUNT = 742886
    TX_COUNT_HEIGHT = 643128
    TX_PER_BLOCK = 2
    RPC_PORT = 17299

    @classmethod
    def genesis_block(cls, block):
        '''Check the Genesis block is the right one for this coin.
        Return the block less its unspendable coinbase.
        '''
        header = cls.block_header(block, 0)
        header_hex_hash = cls.HEADER_HASH_GEN(header)
        if header_hex_hash != cls.GENESIS_HASH:
            raise CoinError('genesis block has hash {} expected {}'
                            .format(header_hex_hash, cls.GENESIS_HASH))
        return header + bytes(1)

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        return cls.HEADER_HASH(header)


class BitcoinCash(BitcoinMixin, Coin):
    NAME = "BitcoinCashABC"
    SHORTNAME = "BCH"
    TX_COUNT = 265479628
    TX_COUNT_HEIGHT = 556592
    TX_PER_BLOCK = 400
    PEERS = [
        'bch.imaginary.cash s t',
        'electroncash.dk s t',
        'wallet.satoshiscoffeehouse.com s t',
    ]
    BLOCK_PROCESSOR = block_proc.LTORBlockProcessor


class Stakenet(Coin):
    NAME = "Stakenet"
    SHORTNAME = "XSN"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("02fe52cc")
    XPRV_VERBYTES = bytes.fromhex("02fe52f8")
    GENESIS_HASH = ('00000c822abdbb23e28f79a49d29b414'
                    '29737c6c7e15df40d1b1f1b35907ae34')
    P2PKH_VERBYTE = bytes.fromhex("4c")
    P2SH_VERBYTES = [bytes.fromhex("10")]
    WIF_BYTE = bytes.fromhex("cc")
    TX_COUNT_HEIGHT = 569399
    TX_COUNT = 2157510
    TX_PER_BLOCK = 4
    RPC_PORT = 62583
    PEERS = []
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon
    DESERIALIZER = lib_tx.DeserializerSegWit

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x11_hash
        return x11_hash.getPoWHash(header)
