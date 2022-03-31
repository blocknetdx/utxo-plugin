from electrumx.server.daemon import Daemon


class SyscoinDaemon(Daemon):

    async def masternode_broadcast(self, params):
        '''Broadcast a transaction to the network.'''
        return await self._send_single('masternodebroadcast', params)

    async def masternode_list(self, params):
        '''Return the masternode status.'''
        return await self._send_single('masternodelist', params)

    async def assetallocationsend(self, asset_guid, from_address, to_address, amount):
        return await self._send_single('assetallocationsend', [int(asset_guid), from_address, to_address, amount])

    async def listassetallocations(self, params):
        return await self._send_single('listassetallocations', [0, 0, {'addresses': params}])

    async def listassetindex(self, page, params):
        return await self._send_single('listassetindex', [page, params])
