// Modules to control application life and create native browser window
const {app, BrowserWindow, Menu,ipcMain} = require('electron')
const path = require('path')
const cryptFunc = require('./src/functions');

// Keep a global reference of the window object, if you don't, the window will
// be closed automatically when the JavaScript object is garbage collected.
let mainWindow;
let lab1Window;
let lab2Window;
let labDiffiHellman;
let labDiffiHellmansub;
let labShamir;
let labAlGamal;

function createWindow () {
  // Create the browser window.
  mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: true
    }
  });

  const createlab1Window = () =>{
    lab1Window= new BrowserWindow({
      width: 600,
      height: 330,
      title: 'Add item',
      icon:__dirname+"/img/icon.jpg",
      webPreferences: {
        nodeIntegration: true
      }
    });
    lab1Window.loadFile('Lab1.html');
    lab1Window.on('close',function () {
      lab1Window = 'null';
    })
  };

  const createlab2Window = () =>{
    lab2Window= new BrowserWindow({
      width: 1000,
      height: 600,
      title: 'RSA алгоритм',
      webPreferences: {
        nodeIntegration: true
      }
    });
    lab2Window.loadFile('./pages/LabRSA.html');
    lab2Window.on('close',function () {
      lab2Window = 'null';
    });
  };

  const createlabDiffiHellman = () =>{
    labDiffiHellman= new BrowserWindow({
      width: 1000,
      height: 300,
      title: 'Алгоритм Диффи-Хеллмана 1й',
      webPreferences: {
        nodeIntegration: true
      }
    });
    labDiffiHellman.loadFile('./pages/LabDiffiHellman.html');
    labDiffiHellman.on('close',function () {
      labDiffiHellman = 'null';
      mainWindow.show();
    });
  };

  const createlabDiffiHellmansub = () =>{
      labDiffiHellmansub= new BrowserWindow({
            width: 1000,
            height: 300,
            title: 'Алгоритм Диффи-Хеллмана 2й',
            webPreferences: {
                nodeIntegration: true
            }
        });
      labDiffiHellmansub.loadFile('./pages/LabDiffiHellmansub.html');
      labDiffiHellmansub.on('close',function () {
          labDiffiHellmansub = 'null';
          mainWindow.show();
        })
    };

  const createlabShamir = () =>{
    labShamir= new BrowserWindow({
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
    labShamir.on('close',function () {
      labShamir = 'null';
      mainWindow.show();
    });
  };

  const createlabAlGamal = () =>{
    labAlGamal= new BrowserWindow({
      width: 1060,
      height: 600,
      title: 'Шифр Эль-Гамаля',
      webPreferences: {
        nodeIntegration: true,
        nodeIntegrationInWorker: true
      }
    });
    labAlGamal.loadFile('./pages/labAlGamal.html');
    mainWindow.hide();
    labAlGamal.on('close',function () {
      labAlGamal = 'null';
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
  ipcMain.on('getKeyDiffiHellman', function (e,data) {
      // console.table(data);
      let output = cryptFunc.DiffiHellman(data.p.toString(),data.q.toString(), data.size);
      // console.log(output);
      labDiffiHellmansub.webContents.send('Key', output);
      labDiffiHellman.webContents.send('Key', output);

  });
    ipcMain.on('labShamirOpen', function () {
        createlabShamir();
        mainWindow.hide();
    });
    ipcMain.on('labAlGamalOpen', function () {
        createlabAlGamal();
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
