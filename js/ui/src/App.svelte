<script lang="ts">
	import Portis from "@portis/web3";
	import { Client, SiweSession } from "@spruceid/siwe-web3modal";
	import Torus from "@toruslabs/torus-embed";
	import WalletConnectProvider from "@walletconnect/web3-provider";
	import Fortmatic from "fortmatic";
	import WalletLink from "walletlink";

	// TODO: REMOVE DEFAULTS:
	// main.ts will parse the params from the server
	export let domain: string;
	export let nonce: string;
	export let redirect: string;
	export let state: string;
	export let oidc_nonce: string;

	let uri: string = window.location.href.split("?")[0];

	// Could be exposed in the future.
	export let useENS: boolean = true;

	$: status = "Not Logged In";

	let client = new Client({
		session: {
			domain,
			uri,
			useENS,
			version: "1",
			// TODO: Vet this as the default statement.
			statement: "Sign-In With Ethereum OpenID-Connect",
		},
		modal: {
			theme: "dark",
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
				portis: {
					package: Portis,
					options: {
						id: process.env.PORTIS_ID,
					},
				},
				fortmatic: {
					package: Fortmatic,
					options: {
						key: process.env.FORTMATIC_KEY,
					},
				},
				"custom-coinbase": {
					display: {
						logo: "img/coinbase.svg",
						name: "Coinbase",
						description: "Scan with WalletLink to connect",
					},
					options: {
						appName: "Sign-In with Ethereum",
						networkUrl: `https://mainnet.infura.io/v3/${process.env.INFURA_ID}`,
						chainId: 1,
						darkMode: false,
					},
					package: WalletLink,
					connector: async (_, options) => {
						const { appName, networkUrl, chainId, darkMode } =
							options;
						const walletLink = new WalletLink({
							appName,
							darkMode,
						});
						const provider = walletLink.makeWeb3Provider(
							networkUrl,
							chainId
						);
						await provider.enable();
						return provider;
					},
				},
			},
		},
	});

	let oidc_nonce_param = "";
	if (oidc_nonce != "") {
		oidc_nonce_param = `&oidc_nonce=${oidc_nonce}`;
	}
	client.on("signIn", (result) => {
		console.log(result);
		window.location.replace(`/sign_in?redirect_uri=${encodeURI(redirect)}&state=${encodeURI(state)}${encodeURI(oidc_nonce_param)}`);
	});
</script>

<main>
	<div>
		<h2>Sign-In With Ethereum</h2>
		<p>{status}</p>
		<!-- TODO: Add copy / info about who is requesting here. -->
		<button
			on:click={() => {
				client.signIn(nonce).catch((e) => {
					console.error(e);
				});
			}}
		>
			Sign In
		</button>
	</div>
</main>

<style>
</style>
