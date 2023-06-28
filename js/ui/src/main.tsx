import React from "react";
import ReactDOM from "react-dom/client";
import { WagmiConfig, createConfig, mainnet } from "wagmi";
import { getDefaultConfig } from "connectkit";
import App from "./App";
import "./index.css";

const config = createConfig(
  getDefaultConfig({
    // Required API Keys
    infuraId: process.env.INFURA_ID,
    walletConnectProjectId: process.env.WALLET_CONNECT_ID ?? '',
    chains: [mainnet],

    // Required
    appName: "SIWE | Devfolio",
    appUrl: "https://devfolio.co", // your app's url
    appIcon: "https://siwe.devfolio.co/favicon.png", // your app's logo,no bigger than 1024x1024px (max. 1MB)
    autoConnect: false,
  })
);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <WagmiConfig config={config}>
      <App />
    </WagmiConfig>
  </React.StrictMode>
);
