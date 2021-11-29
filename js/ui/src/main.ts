import './global.css';

import App from './App.svelte';

const params = new URLSearchParams(window.location.search);

const app = new App({
	target: document.body,
	props: {
		domain: params.get('domain'),
		nonce: params.get('nonce'),
		redirect: params.get('redirect_uri'),
		state: params.get('state'),
		oidc_nonce: params.get('oidc_nonce')
	}
});

export default app;
