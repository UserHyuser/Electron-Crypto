// Modules to control application life and create native browser window
const {app, BrowserWindow, Menu, ipcMain} = require('electron');
const path = require('path');
const cryptFunc = require('./src/functions');

let mainWindow;
let lab1Window;
let lab2Window;
let labDiffiHellman;
let labDiffiHellmansub;
let labShamir;
let labElGamal;
let MD5;
let SHA;
let RSADigSig;
let ElGamalDigSig;
let FIPSDigSig;
let GOSTHash;
let GOSTDigSig;

function createWindow() {
	// Create the browser window.
	mainWindow = new BrowserWindow({
		width: 800,
		height: 600,
		webPreferences: {
			preload: path.join(__dirname, 'preload.js'),
			nodeIntegration: true
		}
	});
	const createlab1Window = () => {
		lab1Window = new BrowserWindow({
			width: 600,
			height: 330,
			title: 'Add item',
			icon: __dirname + "/img/icon.jpg",
			webPreferences: {
				nodeIntegration: true
			}
		});
		lab1Window.loadFile('./pages/Lab1.html');
		lab1Window.on('close', function () {
			lab1Window = 'null';
		})
	};
	const createlab2Window = () => {
		lab2Window = new BrowserWindow({
			width: 1000,
			height: 600,
			title: 'RSA алгоритм',
			webPreferences: {
				nodeIntegration: true
			}
		});
		lab2Window.loadFile('./pages/LabRSA.html');
		lab2Window.on('close', function () {
			lab2Window = 'null';
		});
	};
	const createlabDiffiHellman = () => {
		labDiffiHellman = new BrowserWindow({
			width: 1000,
			height: 300,
			title: 'Алгоритм Диффи-Хеллмана 1й',
			webPreferences: {
				nodeIntegration: true
			}
		});
		labDiffiHellman.loadFile('./pages/LabDiffiHellman.html');
		labDiffiHellman.on('close', function () {
			labDiffiHellman = 'null';
			mainWindow.show();
		});
	};
	const createlabDiffiHellmansub = () => {
		labDiffiHellmansub = new BrowserWindow({
			width: 1000,
			height: 300,
			title: 'Алгоритм Диффи-Хеллмана 2й',
			webPreferences: {
				nodeIntegration: true
			}
		});
		labDiffiHellmansub.loadFile('./pages/LabDiffiHellmansub.html');
		labDiffiHellmansub.on('close', function () {
			labDiffiHellmansub = 'null';
			mainWindow.show();
		})
	};
	const createlabShamir = () => {
		labShamir = new BrowserWindow({
			width: 1000,
			height: 600,
			title: 'Шифр Шамира',
			webPreferences: {
				nodeIntegration: true,
				nodeIntegrationInWorker: true
			}
		});
		labShamir.loadFile('./pages/labShamir.html');
		mainWindow.hide();
		labShamir.on('close', function () {
			labShamir = 'null';
			mainWindow.show();
		});
	};
	const createlabElGamal = () => {
		labElGamal = new BrowserWindow({
			width: 1060,
			height: 600,
			title: 'Шифр Эль-Гамаля',
			webPreferences: {
				nodeIntegration: true,
				nodeIntegrationInWorker: true
			}
		});
		labElGamal.loadFile('./pages/labElGamal.html');
		mainWindow.hide();
		labElGamal.on('close', function () {
			labElGamal = 'null';
			mainWindow.show();
		});
	};
	const createMD5 = () => {
		MD5 = new BrowserWindow({
			width: 1060,
			height: 600,
			title: 'MD5 Hash Prog',
			webPreferences: {
				nodeIntegration: true,
				nodeIntegrationInWorker: true
			}
		});
		MD5.loadFile('./pages/MD5.html');
		mainWindow.hide();
		MD5.on('close', function () {
			MD5 = 'null';
			mainWindow.show();
		});
	};
	const createSHA = () => {
		SHA = new BrowserWindow({
			width: 1060,
			height: 600,
			title: 'SHA Hash Prog',
			webPreferences: {
				nodeIntegration: true,
				nodeIntegrationInWorker: true
			}
		});
		SHA.loadFile('./pages/SHA.html');
		mainWindow.hide();
		SHA.on('close', function () {
			SHA = 'null';
			mainWindow.show();
		});
	};
	const createRSADigSig = () => {
		RSADigSig = new BrowserWindow({
			width: 1060,
			height: 600,
			title: 'RSA Digital Signature',
			webPreferences: {
				nodeIntegration: true,
				nodeIntegrationInWorker: true
			}
		});
		RSADigSig.loadFile('./pages/RSA_digital_signature.html');
		mainWindow.hide();
		RSADigSig.on('close', function () {
			RSADigSig = 'null';
			mainWindow.show();
		});
	};
	const createElGamalDigSig = () => {
		ElGamalDigSig = new BrowserWindow({
			width: 1060,
			height: 600,
			title: 'ElGamal Digital Signature',
			webPreferences: {
				nodeIntegration: true,
				nodeIntegrationInWorker: true
			}
		});
		ElGamalDigSig.loadFile('./pages/ElGamal_digital_signature.html');
		mainWindow.hide();
		ElGamalDigSig.on('close', function () {
			ElGamalDigSig = 'null';
			mainWindow.show();
		});
	};
	const createFIPSDigSig = () => {
		FIPSDigSig = new BrowserWindow({
			width: 1060,
			height: 600,
			title: 'FIPS 186 standard Digital Signature',
			webPreferences: {
				nodeIntegration: true,
				nodeIntegrationInWorker: true
			}
		});
		FIPSDigSig.loadFile('./pages/FIPS_186_digital_signature.html');
		mainWindow.hide();
		FIPSDigSig.on('close', function () {
			FIPSDigSig = 'null';
			mainWindow.show();
		});
	};
	const createGOSTHash = () => {
		GOSTHash = new BrowserWindow({
			width: 1060,
			height: 600,
			title: 'GOST R 34.11.94',
			webPreferences: {
				nodeIntegration: true,
				nodeIntegrationInWorker: true
			}
		});
		GOSTHash.loadFile('./pages/GOST_R_34.11.94.html');
		mainWindow.hide();
		GOSTHash.on('close', function () {
			GOSTHash = 'null';
			mainWindow.show();
		});
	};
	const createGOSTDigSig = () => {
		GOSTDigSig = new BrowserWindow({
			width: 1060,
			height: 600,
			title: 'GOST R 34.11.94',
			webPreferences: {
				nodeIntegration: true,
				nodeIntegrationInWorker: true
			}
		});
		GOSTDigSig.loadFile('./pages/GOST_digital_signature.html');
		mainWindow.hide();
		GOSTDigSig.on('close', function () {
			GOSTDigSig = 'null';
			mainWindow.show();
		});
	};


	ipcMain.on('lab1Open', function () {
		createlab1Window();
	});
	ipcMain.on('lab2Open', function () {
		createlab2Window();
	});
	ipcMain.on('labDiffiHellmanOpen', function () {
		createlabDiffiHellman();
		createlabDiffiHellmansub();
		mainWindow.hide();
	});
	ipcMain.on('getKeyDiffiHellman', function (e, data) {
		// console.table(data);
		let output = cryptFunc.DiffiHellman(data.p.toString(), data.q.toString(), data.size);
		// console.log(output);
		labDiffiHellmansub.webContents.send('Key', output);
		labDiffiHellman.webContents.send('Key', output);
	});
	ipcMain.on('labShamirOpen', function () {
		createlabShamir();
		mainWindow.hide();
	});
	ipcMain.on('labElGamalOpen', function () {
		createlabElGamal();
		mainWindow.hide();
	});
	ipcMain.on('MD5Open', function () {
		createMD5();
		mainWindow.hide();
	});
	ipcMain.on('SHAOpen', function () {
		createSHA();
		mainWindow.hide();
	});
	ipcMain.on('RSADigSigOpen', function () {
		createRSADigSig();
		mainWindow.hide();
	});
	ipcMain.on('ElGamalDigSigOpen', function () {
		createElGamalDigSig();
		mainWindow.hide();
	});
	ipcMain.on('FIPSDigSigOpen', function () {
		createFIPSDigSig();
		mainWindow.hide();
	});
	ipcMain.on('GOSTOpen', function () {
		createGOSTHash();
		mainWindow.hide();
	});
	ipcMain.on('GOSTDigSigOpen', function () {
		createGOSTDigSig();
		mainWindow.hide();
	});

	// and load the index.html of the app.
	mainWindow.loadFile('index.html');
	// Menu.setApplicationMenu(null);
	// Open the DevTools.
	// mainWindow.webContents.openDevTools()
	mainWindow.on('closed', function () {
		// Dereference the window object, usually you would store windows
		// in an array if your app supports multi windows, this is the time
		// when you should delete the corresponding element.
		mainWindow = null;
		app.quit();
	})
}

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.on('ready', createWindow);
// Quit when all windows are closed.
app.on('window-all-closed', function () {
	// On macOS it is common for applications and their menu bar
	// to stay active until the user quits explicitly with Cmd + Q
	if (process.platform !== 'darwin') app.quit()
});
app.on('activate', function () {
	// On macOS it's common to re-create a window in the app when the
	// dock icon is clicked and there are no other windows open.
	if (mainWindow === null) createWindow()
});
// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and require them here.
