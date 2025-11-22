var MD5String = Module.findBaseAddress("TDProtocol").add(0x7BD4);

Interceptor.attach(MD5String, {
    onEnter: function (args) {
        // Hook 时保存参数，避免被修改
        this.arg0 = args[0];
        this.arg1 = args[1];

        console.log("MD5String() arg0 onEnter:", hexdump(this.arg0.readPointer()));
        console.log("MD5String() arg1 onEnter:", hexdump(this.arg1));
    },

    onLeave: function (retval) {
        console.log("MD5String() arg1 onLeave:", hexdump(this.arg1));
        console.log("MD5String() retval onLeave:", retval);
    }
});
