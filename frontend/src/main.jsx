import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { AttribIQProvider } from './context/AttribIQContext.jsx';
import App from './App.jsx';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <AttribIQProvider>
        <App />
      </AttribIQProvider>
    </BrowserRouter>
  </React.StrictMode>
);
