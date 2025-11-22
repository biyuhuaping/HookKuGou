// 运行方式：frida -U -f com.kugou.kugou1002 -l Tools/tmp.js 
//0x11331B4F0
var tmpFun = Module.findBaseAddress("kugou").add(0x113045DE0);
Interceptor.attach(tmpFun, {
    onEnter: function (args) {
        console.log('👉 tmpFun onEnter');
        // console.log(hexdump(args[0]));
    },
    onLeave: function (retval) {
        console.log('👉 tmpFun onLeave');
        // console.log(hexdump(retval));
    }
});