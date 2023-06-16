<script lang="ts">
	import { Client } from '@spruceid/siwe-web3modal';
	import Torus from '@toruslabs/torus-embed';
	import WalletConnectProvider from '@walletconnect/web3-provider';
	import CoinbaseWalletSDK from '@coinbase/wallet-sdk';

	// TODO: REMOVE DEFAULTS:
	// main.ts will parse the params from the server
	export let domain: string;
	export let nonce: string;
	export let redirect: string;
	export let state: string;
	export let oidc_nonce: string;
	export let client_id: string;

	// Could be exposed in the future.
	export let useENS: boolean = true;

	$: status = 'Not Logged In';

	let client = new Client({
		session: {
			domain: window.location.host,
			uri: window.location.origin,
			useENS,
			version: '1',
			// TODO: Vet this as the default statement.
			statement: `You are signing-in to ${domain}.`,
			resources: [redirect],
		},
		modal: {
			providerOptions: {
				walletconnect: {
					package: WalletConnectProvider,
					options: {
						infuraId: process.env.INFURA_ID,
						pollingInterval: 100000,
					},
				},
				torus: {
					package: Torus,
				},
				walletlink: {
					package: CoinbaseWalletSDK,
					options: {
						appName: 'Sign-In with Ethereum',
						infuraId: process.env.INFURA_ID,
					},
				},
			},
		},
	});

	let oidc_nonce_param = '';
	if (oidc_nonce != null && oidc_nonce != '') {
		oidc_nonce_param = `&oidc_nonce=${oidc_nonce}`;
	}
	client.on('signIn', (result) => {
		console.log(result);
		window.location.replace(
			`/sign_in?redirect_uri=${encodeURI(redirect)}&state=${encodeURI(state)}&client_id=${encodeURI(
				client_id,
			)}${encodeURI(oidc_nonce_param)}`,
		);
	});
</script>

<div class="bg-white md:bg-gray-bg h-full w-full flex flex-col items-center font-nunito justify-start">
	<img src="/img/devfolio-logo-full.svg" alt="Devfolio logo" height={36} width={174} class="mt-10 h-[27px] w-[135px] md:h-[36px] md:w-[174px] md:mt-16"/>
	<div class="w-full md:w-[476px] bg-white md:rounded-2xl md:shadow-blue-1 pt-2 md:pt-8 p-8 mt-10">
		<h1 class=" text-2xl font-extrabold text-black">Sign in with Ethereum</h1>
		<p class="mt-1 text-base font-normal text-gray-7">Continue below to sign to Devfolio</p>

		<div class="flex flex-col mt-6 w-full justify-center">
			<img
				src="/img/sign-in-ethereum.svg"
				alt="An illustration showing a wallet linking"
				height="191"
				width="191"
				class="mx-auto"
			/>

			<div class="mt-8 flex flex-col gap-4">
				<button
					class="bg-white rounded-lg shadow-blue-1 px-8 py-3 h-14 border border-solid border-gray-3 text-lg font-bold text-gray-8 flex items-center justify-center gap-2 hover:bg-blue-0 hover:border-blue-1 active:border-blue-1 active:bg-blue-0 active:shadow-inner"
					on:click={() => {
						client.signIn(nonce).catch((e) => {
							console.error(e);
						});
					}}
				>
					<img src="/img/ethereum-logo.svg" alt="Ethereum Logo" height={24} width={24} class=" max-h-6 max-w-6" />
					Continue with Ethereum
				</button>
				<div class=" text-sm font-semibold text-gray-6 text-center">
					By continuing you agree to the <a href="https://devfolio.co/terms-of-use" target="_blank" rel="noreferrer noopener">Terms of Use</a> and
					<a href="https://devfolio.co/privacy-policy" target="_blank" rel="noreferrer noopener">Privacy Policy</a>.
				</div>
			</div>
		</div>
	</div>
</div>

<style global lang="postcss">
	@tailwind base;
	@tailwind components;
	@tailwind utilities;

	a {
		@apply text-blue-4B;
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
