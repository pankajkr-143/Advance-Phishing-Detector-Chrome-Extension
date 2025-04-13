# Advance Phishing Detector Chrome Extension

A lightweight and efficient Chrome extension designed to detect and warn users about potential phishing websites in real-time. By analyzing URLs and page content, it helps protect users from malicious sites attempting to steal sensitive information.

## 🚀 Features

- **Real-time Phishing Detection**:Analyzes the current webpage to identify phishing threats
- **User Alerts**:Provides immediate warnings when a suspicious site is detected
- **Privacy-Focused**:Operates entirely within the browser without collecting user data
- **Lightweight Design**:Minimal impact on browser performance

## 🧩 Installation

### 1. Clone the Repository

```bas
git clone https://github.com/pankajkr-143/Advance-Phishing-Detector-Chrome-Extension.gt
cd Advance-Phishing-Detector-Chrome-Extension/projet
```


### 2. Load the Extension in Chrome

1 Open Google Chrome and navigate to `chrome://extensions/.
2 Enable **Developer mode** by toggling the switch in the top-right corne.
3 Click on **Load unpacked*.
4 Select the `project` directory from the cloned repositor.
The extension should now appear in your list of Chrome extension.

## 🧪 Testing the Extension

To verify the extension's functionality:

. Ensure the extension is enabled in `chrome://extensions`.
. Visit known phishing test sites, such s:
   - [PhishTank](https://www.phishtank.com/)
   - [Example Phishing Page](https://example.com/phishing-test) *(Replace with actual test URLs)*
. Observe if the extension triggers a warning upon visiting these sits.

## 🛠️ Development

### Project Structue

```plaintext
project/
├── background.js
├── contentScript.js
├── manifest.json
├── popup.html
├── popup.js
├── styles.css
├── icons/
│   └── icon.png
├── src/
│   └── [Source files]
├── scripts/
│   └── [Build or utility scripts]
├── package.json
├── vite.config.ts
└── ...
``


### Scripts

- **Build*: Compiles the extension for producton.
  ```bas
  npm run bild
  ```

- **Dev*: Starts a development server with live relad.
  ```bas
  npm rundev
  ```

- **Lint*: Checks code for linting errrs.
  ```bas
  npm run int
  ```


### Dependencis

Ensure you have the following instaled:

- **Node.js*: v14 or hiher
- **npm*: v6 or hiher

Install project dependencies:

```bsh
npm insall
```


## 📄 Licese

This project is licensed under the [MIT License](LICESE).

## 🙌 Acknowledgemnts

Thanks to all contributors and the open-source community for their invaluable resources and suport.
---

*Note: This README is based on the available information from the repository. For detailed documentation and updates, please refer to the [GitHub repository](https://github.com/pankajkr-143/Advance-Phishing-Detector-Chrome-Extenson).* 
