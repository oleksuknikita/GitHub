import os from "node:os";
const greeting = "РџСЂРёРІС–С‚, РєР»С–С”РЅС‚-СЃРµСЂРІРµСЂРЅРёР№ СЃРІС–С‚!";

if (os.platform() === "win32") {
  console.log("Windows");
}
console.log(greeting);

