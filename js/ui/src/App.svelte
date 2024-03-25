<script lang="ts">
	import { onMount } from 'svelte';
	
	
	import { createWeb3Modal, defaultWagmiConfig } from '@web3modal/wagmi'

	import { arbitrum, mainnet, polygon } from '@wagmi/core/chains';
	import { getAccount, signMessage, reconnect, getConnections} from '@wagmi/core';
	import { SiweMessage } from 'siwe';
	import Cookies from 'js-cookie';

	// TODO: REMOVE DEFAULTS:
	// main.ts will parse the params from the server
	export let domain: string;
	export let nonce: string;
	export let redirect: string;
	export let state: string;
	export let oidc_nonce: string;
	export let client_id: string;
	const projectId: string = process.env.PROJECT_ID;

	$: status = 'Not Logged In';

	const chains = [mainnet, arbitrum, polygon];

	const config = defaultWagmiConfig({
		chains,
		projectId,
		enableCoinbase: false,
		enableInjected: false,
	})

	const web3modal = createWeb3Modal({
		defaultChain: mainnet,
		wagmiConfig: config,
  		projectId,
		themeMode: 'dark',
		featuredWalletIds: [],
	});

	reconnect(config)

	let client_metadata = {};
	onMount(async () => {
		try {
			client_metadata = fetch(`${window.location.origin}/client/${client_id}`).then((response) => response.json());
		} catch (e) {
			console.error(e);
		}
	});

	web3modal.subscribeState(async (newState) => {

		const account = getAccount(config);

		if (account.isConnected) {
			try {
				const expirationTime = new Date(
					new Date().getTime() + 2 * 24 * 60 * 60 * 1000, // 48h
				);

				const msgToSign = new SiweMessage({
					domain: window.location.host,
					address: account.address,
					chainId: account.chainId,
					expirationTime: expirationTime.toISOString(),
					uri: window.location.origin,
					version: '1',
					statement: `You are signing-in to ${window.location.host}.`,
					nonce,
					resources: [redirect],
				});

				const preparedMessage = msgToSign.prepareMessage();
				
				await new Promise((resolve) => setTimeout(resolve, 1000));
				
				const signature = await signMessage(config,{
					message: preparedMessage,
				});

				const session = {
					message: new SiweMessage(preparedMessage),
					raw: msgToSign,
					signature,
				};
				Cookies.set('siwe', JSON.stringify(session), {
					expires: expirationTime,
				});

				window.location.replace(
					`/sign_in?redirect_uri=${encodeURI(redirect)}&state=${encodeURI(state)}&client_id=${encodeURI(
						client_id,
					)}${encodeURI(oidc_nonce_param)}`,
				);
				return;
			} catch (e) {
				console.error(e);
			}
		}
	});

	let oidc_nonce_param = '';
	if (oidc_nonce != null && oidc_nonce != '') {
		oidc_nonce_param = `&oidc_nonce=${oidc_nonce}`;
	}
</script>

<div
	class="bg-no-repeat bg-cover bg-center bg-swe-landing font-satoshi bg-gray flex-grow w-full h-screen items-center flex justify-center flex-wrap flex-col"
	style="background-image: url('img/swe-landing.svg');"
>
	<div class="w-96 text-center bg-white rounded-20 text-grey flex h-100 flex-col p-12 shadow-lg shadow-white">
		{#if client_metadata.logo_uri}
			<div class="flex justify-evenly items-stretch">
				<img height="72" width="72" class="self-center mb-8" src="img/modal_icon.png" alt="Ethereum logo" />
				<img height="72" width="72" class="self-center mb-8" src={client_metadata.logo_uri} alt="Client logo" />
			</div>
		{:else}
			<img height="72" width="72" class="self-center mb-8" src="img/modal_icon.png" alt="Ethereum logo" />
		{/if}
		<h5>Welcome</h5>
		<span class="text-xs">
			Sign-In with Ethereum to continue to {client_metadata.client_name ? client_metadata.client_name : domain}
		</span>

		<button
			class="h-12 border hover:scale-105 justify-evenly shadow-xl border-white mt-4 duration-100 ease-in-out transition-all transform flex items-center"
			on:click={() => {
				web3modal.open();
			}}
		>
			<svg
				xmlns="http://www.w3.org/2000/svg"
				clip-rule="evenodd"
				fill-rule="evenodd"
				stroke-linejoin="round"
				stroke-miterlimit="1.41421"
				viewBox="170 30 220 350"
				class="w-6 h-8"
			>
				<g fill-rule="nonzero" transform="matrix(.781253 0 0 .781253 180 37.1453)">
					<path d="m127.961 0-2.795 9.5v275.668l2.795 2.79 127.962-75.638z" fill="#343434" /><path
						d="m127.962 0-127.962 212.32 127.962 75.639v-133.801z"
						fill="#8c8c8c"
					/>
					<path d="m127.961 312.187-1.575 1.92v98.199l1.575 4.601 128.038-180.32z" fill="#3c3c3b" /><path
						d="m127.962 416.905v-104.72l-127.962-75.6z"
						fill="#8c8c8c"
					/>
					<path d="m127.961 287.958 127.96-75.637-127.96-58.162z" fill="#141414" /><path
						d="m.001 212.321 127.96 75.637v-133.799z"
						fill="#393939"
					/>
				</g>
			</svg>
			<p class="font-bold">Sign-In with Ethereum</p>
		</button>
		<div class="self-center mt-auto text-center font-semibold text-xs">
			By using this service you agree to the <a href="/legal/terms-of-use.pdf">Terms of Use</a> and
			<a href="/legal/privacy-policy.pdf">Privacy Policy</a>.
		</div>

		{#if client_metadata.client_uri}
			<span class="text-xs mt-4">Request linked to {client_metadata.client_uri}</span>
		{/if}
	</div>
</div>

<style global lang="postcss">
	@tailwind base;
	@tailwind components;
	@tailwind utilities;

	.tooltip {
		@apply invisible absolute;
	}

	.has-tooltip:hover .tooltip {
		@apply visible z-50;
	}
	html,
	body {
		position: relative;
		width: 100vw;
		height: 100vh;
		margin: 0px;
		padding: 0px;
		font-size: 18px;
		background: #ecf2fe;
		display: flex;
		flex-direction: column;
		overflow-x: hidden;
		@apply font-satoshi;
	}

	h1,
	h2,
	h3,
	h4,
	h5,
	h6 {
		@apply font-extrabold;
		@apply font-satoshi;
	}

	h1 {
		font-size: 76px;
		line-height: 129px;
		letter-spacing: -4.5%;
	}

	h2 {
		font-size: 66px;
		line-height: 101px;
		letter-spacing: -3%;
	}

	h3 {
		font-size: 52px;
		line-height: 80px;
		letter-spacing: -1.5%;
	}

	h4 {
		font-size: 48px;
		line-height: 63px;
		letter-spacing: -1%;
	}

	h5 {
		font-size: 32px;
		line-height: 49px;
		letter-spacing: -0.5%;
	}

	h6 {
		font-size: 24px;
		line-height: 37px;
		letter-spacing: -0.5%;
	}

	body {
		color: #222222;
	}

	a {
		text-decoration: none;
		color: #04d2ca;
	}

	td,
	th {
		font-family: 'Satoshi';
		font-weight: 400;
	}

	pre {
		white-space: pre-wrap; /* Since CSS 2.1 */
		white-space: -moz-pre-wrap; /* Mozilla, since 1999 */
		white-space: -pre-wrap; /* Opera 4-6 */
		white-space: -o-pre-wrap; /* Opera 7 */
		word-wrap: break-word; /* Internet Explorer 5.5+ */
	}

	.web3modal-modal-lightbox {
		z-index: 30 !important;
	}

	.walletconnect-modal__base {
		background-color: #273137 !important;
	}

	.walletconnect-qrcode__text {
		color: white !important;
	}

	.walletconnect-modal__mobile__toggle {
		background: rgba(255, 255, 255, 0.1) !important;
	}

	.walletconnect-qrcode__image {
		border: 24px solid white !important;
		border-radius: 8px !important;
	}

	.walletconnect-modal__base__row:hover {
		background: rgba(255, 255, 255, 0.1) !important;
	}

	.walletconnect-modal__mobile__toggle_selector {
		background: rgba(255, 255, 255, 0.2) !important;
	}

	/**
	Custom scrollbar settings
	*/
	::-webkit-scrollbar-track {
		border-radius: 8px;
		background-color: #ccc;
	}

	::-webkit-scrollbar-thumb {
		border-radius: 8px;
		background-color: #888;
	}
	::-webkit-scrollbar {
		height: 6px;
		border-radius: 8px;
		width: 6px;
		background-color: #ccc;
	}

	.grecaptcha-badge {
		visibility: hidden;
	}
</style>
