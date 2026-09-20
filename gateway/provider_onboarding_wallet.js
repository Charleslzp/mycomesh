// The wallet owns signing and sending. This page never receives its keys.
(() => {
  const button = document.querySelector('#authorize-wallet');
  if (!button) return;
  const form = document.querySelector('#setup');
  const message = document.querySelector('#authorization-message');
  const address = document.querySelector('#payout_address');
  const pin = JSON.parse(document.querySelector('#authorization-pin').textContent);
  const provider = () => window.okxwallet?.request ? window.okxwallet
    : window.ethereum?.request ? window.ethereum : null;
  let busy = false;
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const validAddress = (value) => typeof value === 'string' && /^0x[0-9a-f]{40}$/i.test(value);
  const checkPlan = (data, account) => {
    const tx = data?.plan?.transaction;
    if (data?.ok !== true || !tx || typeof data.authorized !== 'boolean') {
      throw new Error(data?.error || 'Could not verify the authorization plan.');
    }
    if (tx.chainId !== pin.chainId || tx.to !== pin.contract || tx.data !== pin.data
        || tx.value !== '0x0' || tx.from?.toLowerCase() !== account.toLowerCase()) {
      throw new Error('The authorization plan does not match this Provider and wallet.');
    }
    return { chainId: pin.chainId, from: account, to: pin.contract, data: pin.data, value: '0x0' };
  };
  const readStatus = async (account, action = null) => {
    const response = await fetch(action ? '/api/provider-authorization-intent' : '/api/provider-authorization', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...Object.fromEntries(new FormData(form).entries()), ...(action || {}) }),
    });
    const data = await response.json();
    return { data, transaction: checkPlan(data, account) };
  };
  button.addEventListener('click', async () => {
    if (busy) return;
    busy = true;
    button.disabled = true;
    try {
      const wallet = provider();
      if (!wallet) throw new Error('Open this page in a browser with your wallet extension enabled.');
      message.textContent = 'Connect the wallet that receives your earnings.';
      const accounts = await wallet.request({ method: 'eth_requestAccounts' });
      const account = accounts?.[0];
      if (!validAddress(account)) throw new Error('The wallet did not return a valid account.');
      if (!address.value.trim()) address.value = account;
      if (address.value.trim().toLowerCase() !== account.toLowerCase()) {
        throw new Error('The connected wallet is different from the payout address. Switch accounts or correct the address.');
      }
      if (!pin.persistent) {
        message.textContent = 'Saving your settings first. The next step authorizes the persisted Provider identity.';
        form.requestSubmit();
        return;
      }
      let state = await readStatus(account);
      if (!state.data.authorized) {
        if (state.data.pending) {
          throw new Error('An authorization may already be pending. Check your wallet; no duplicate transaction was sent.');
        }
        if ((await wallet.request({ method: 'eth_chainId' })) !== pin.chainId) {
          await wallet.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: pin.chainId }] });
        }
        if ((await wallet.request({ method: 'eth_chainId' })) !== pin.chainId) {
          throw new Error('The wallet is still on a different network.');
        }
        const current = await wallet.request({ method: 'eth_accounts' });
        if (current?.[0]?.toLowerCase() !== account.toLowerCase()) {
          throw new Error('The wallet account changed. Reconnect before authorizing.');
        }
        message.textContent = 'Review and approve the one-time authorization in your wallet. Network gas applies.';
        // The server commits a persistent, atomic send fence first. This also
        // covers multiple tabs and later launches on another loopback port.
        const reserved = await readStatus(account, { action: 'reserve' });
        if (reserved.data.authorized) {
          message.textContent = 'Wallet authorization verified. Continuing connection checks.';
          form.requestSubmit();
          return;
        }
        const intent = reserved.data.intent_id;
        if (typeof intent !== 'string' || !/^[0-9a-f]{48}$/.test(intent)) {
          throw new Error('The network could not safely reserve a wallet authorization.');
        }
        let hash;
        try {
          hash = await wallet.request({ method: 'eth_sendTransaction', params: [state.transaction] });
        } catch (error) {
          if (error?.code === 4001) await readStatus(account, { action: 'rejected', intent_id: intent, wallet_error_code: 4001 });
          throw error;
        }
        if (typeof hash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(hash)) {
          throw new Error('The wallet result is uncertain. Check the wallet before retrying.');
        }
        await readStatus(account, { action: 'submitted', intent_id: intent, tx_hash: hash });
        message.textContent = 'Authorization submitted. Waiting for the network to verify it…';
        for (let attempt = 0; attempt < 30; attempt += 1) {
          await pause(2000);
          state = await readStatus(account);
          if (state.data.authorized) break;
        }
        if (!state.data.authorized) throw new Error('Authorization is still pending. Check your wallet; do not send again.');
      }
      message.textContent = 'Wallet authorization verified. Continuing sign-in and network connection checks.';
      form.requestSubmit();
    } catch (error) {
      message.textContent = error?.message || 'Wallet authorization could not be completed.';
    } finally {
      busy = false;
      button.disabled = false;
    }
  });
})();
