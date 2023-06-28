import React from "react";
import { ConnectKitButton, ConnectKitProvider } from "connectkit";
import { SiweMessage } from "siwe";
import { useAccount } from "wagmi";
import Cookies from "js-cookie";
import devfolioLogoFull from "./assets/devfolio-logo-full.svg";
import signInWithEthereum from "./assets/sign-in-ethereum.svg";
import ethereumLogo from "./assets/ethereum-logo.svg";


type ACTION_TYPE = 'signin' | 'signup' | 'connect';

const params = new URLSearchParams(window.location.search);
const nonce = params.get("nonce") ?? "";
const redirect = params.get("redirect_uri") ?? "";
const state = params.get("state") ?? "";
const oidc_nonce = params.get("oidc_nonce") ?? "";
const client_id = params.get("client_id") ?? "";
const action = params.get("action") as (ACTION_TYPE | undefined) ?? "signin";

const TITLE: Record<ACTION_TYPE, string> = {
  signin: "Sign in with Ethereum",
  signup: "Sign up with Ethereum",
  connect: "Link your Ethereum Wallet",
};

const DESCRIPTION: Record<ACTION_TYPE, string> = {
  signin: "Continue below to sign in to Devfolio.",
  signup: "In the next step, we will ask you to provide your email address.",
  connect: "Continue below to connect your Ethereum Wallet to Devfolio.",
};

const SIGNING_MESSAGE: Record<ACTION_TYPE, string> = {
  signin: `You are signing-in to Devfolio.`,
  signup: `You are signing-up to Devfolio.`,
  connect: `You are connecting your Ethereum Wallet to Devfolio.`,
}

function App() {
  const account = useAccount();

  React.useEffect(() => {
    const handleSignInWithEthereum = async ({
      address,
    }: {
      address?: string;
    }) => {
      try {
        const expirationTime = new Date(
          new Date().getTime() + 2 * 24 * 60 * 60 * 1000 // 48h
        );

        const chainId = await account.connector?.getChainId();
        const signMessage = new SiweMessage({
          domain: window.location.host,
          address: address,
          chainId,
          expirationTime: expirationTime.toISOString(),
          uri: window.location.origin,
          version: "1",
          statement: SIGNING_MESSAGE[action],
          nonce,
          resources: [redirect],
        }).prepareMessage();
        const walletClient = await account.connector?.getWalletClient();

        const signature = await walletClient?.signMessage({
          account: account.address,
          message: signMessage,
        });

        const message = new SiweMessage(signMessage);
        const session = {
          message,
          raw: signMessage,
          signature,
        };
        Cookies.set("siwe", JSON.stringify(session), {
          expires: expirationTime,
        });

        window.location.replace(
          `/sign_in?redirect_uri=${encodeURI(redirect)}&state=${encodeURI(
            state
          )}&client_id=${encodeURI(client_id)}${encodeURI(oidc_nonce)}`
        );
        return;
      } catch (e) {
        console.error(e);
      }
    };
    if (typeof account.address === "string") {
      handleSignInWithEthereum({ address: account.address });
    }
  }, [account]);

  return (
    <div className="bg-white md:bg-gray-bg h-full w-full flex flex-col items-center font-nunito justify-start">
      <img
        src={devfolioLogoFull}
        alt="Devfolio logo"
        height={36}
        width={174}
        className="mt-10 h-[27px] w-[135px] md:h-[36px] md:w-[174px] md:mt-16"
      />
      <div className="w-full md:w-[476px] bg-white md:rounded-2xl md:shadow-blue-1 pt-2 md:pt-8 p-8 mt-10">
        <h1 className=" text-2xl font-extrabold text-black">
          {TITLE[action]}
        </h1>
        <p className="mt-1 text-base font-normal text-gray-7">
          {DESCRIPTION[action]}
        </p>

        <div className="flex flex-col mt-6 w-full justify-center">
          <img
            src={signInWithEthereum}
            alt="An illustration showing a wallet linking"
            height="191"
            width="191"
            className="mx-auto"
          />

          <div className="mt-8 flex flex-col gap-4">
            <ConnectKitProvider
              theme="soft"
              debugMode
              customTheme={{
                "--ck-font-family": '"Nunito Sans", sans-serif',
                "--ck-primary-button-font-weight": 700,
                "--ck-modal-heading-font-weight": 800,
                "--ck-secondary-button-font-weight": 600,
              }}
            >
              <ConnectKitButton.Custom>
                {({ show }) => (
                  <button
                    onClick={show}
                    className="bg-white rounded-lg px-8 py-3 h-14 border border-solid border-gray-3 text-lg font-bold text-gray-8 flex items-center justify-center gap-2 hover:bg-blue-0 hover:border-blue-1 active:border-blue-1 active:bg-blue-0 active:shadow-inner"
                  >
                    <img
                      src={ethereumLogo}
                      alt="Ethereum Logo"
                      height={24}
                      width={24}
                      className=" max-h-6 max-w-6"
                    />
                    Continue with Ethereum
                  </button>
                )}
              </ConnectKitButton.Custom>
            </ConnectKitProvider>
            {/* <ConnectKitButton /> */}
            <div className=" text-sm text-gray-6 text-center">
              By continuing you agree to the&nbsp;
              <a
                href="https://devfolio.co/terms-of-use"
                target="_blank"
                rel="noreferrer noopener"
              >
                Terms of Use
              </a>
              &nbsp; and&nbsp;
              <a
                href="https://devfolio.co/privacy-policy"
                target="_blank"
                rel="noreferrer noopener"
              >
                Privacy Policy
              </a>
              .
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
