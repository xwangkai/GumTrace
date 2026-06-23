let traceSoName = 'libGumTrace.so'
let targetSo = 'libtarget.so'

let gumtrace_init = null
let gumtrace_run = null
let gumtrace_unrun = null

function loadGumTrace() {
    let dlopen = new NativeFunction(Module.findGlobalExportByName('dlopen'), 'pointer', ['pointer', 'int'])
    let dlsym = new NativeFunction(Module.findGlobalExportByName('dlsym'), 'pointer', ['pointer', 'pointer'])

    let soHandle = dlopen(Memory.allocUtf8String('/data/local/tmp/' + traceSoName), 2)
    console.log('GumTrace loaded:', soHandle)

    gumtrace_init = new NativeFunction(dlsym(soHandle, Memory.allocUtf8String('init')), 'void', ['pointer', 'pointer', 'int', 'pointer'])
    gumtrace_run = new NativeFunction(dlsym(soHandle, Memory.allocUtf8String('run')), 'void', [])
    gumtrace_unrun = new NativeFunction(dlsym(soHandle, Memory.allocUtf8String('unrun')), 'void', [])
}

function startTrace() {
    loadGumTrace()

    let moduleNames = Memory.allocUtf8String(targetSo)
    let outputPath = Memory.allocUtf8String('/data/data/com.example.app/trace.log')
    let threadId = 0   // 0 = 当前线程
    let options = Memory.alloc(8)

    // 0 = Stand 模式
    // 1 = DEBUG 模式
    // 2 = Stable 模式
    // 3 = BLOCK 模式
    options.writeU64(3)

    console.log('start trace')

    gumtrace_init(moduleNames, outputPath, threadId, options)
    gumtrace_run()
}

function stopTrace() {
    console.log('stop trace')
    gumtrace_unrun()
}

// Warning: All apis from Frida 17

let isTrace = false
function hook() {
    let dlopen_ext = Module.getGlobalExportByName('android_dlopen_ext')
    Interceptor.attach(dlopen_ext, {
        onEnter(args) {
            let pathSo = args[0].readCString()
            if (pathSo.indexOf(targetSo) > -1) {
                this.can = true
            }
        },
        onLeave() {
            if (this.can) {

                // 示例：hook 目标函数，在其执行期间进行追踪
                let targetModule = Process.findModuleByName(targetSo)
                Interceptor.attach(targetModule.base.add(0x1234), {
                    onEnter() {
                        if (isTrace === false) {
                            isTrace = true
                            startTrace()
                            this.tracing = true
                        }
                    },
                    onLeave() {
                        if (this.tracing) {
                            stopTrace()
                        }
                    }
                })

            }
        }
    })
}

setImmediate(hook)
