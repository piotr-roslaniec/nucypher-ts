import { Config, DAppProvider } from '@usedapp/core';
import React, { StrictMode } from 'react';
import * as ReactDOMClient from 'react-dom/client';

import App from './App';

const config: Config = {
  readOnlyChainId: 80002,
};
const rootElement = document.getElementById('root');

if (rootElement) {
  ReactDOMClient.createRoot(rootElement).render(
    <StrictMode>
      <DAppProvider config={config}>
        <App />
      </DAppProvider>
    </StrictMode>,
  );
}
