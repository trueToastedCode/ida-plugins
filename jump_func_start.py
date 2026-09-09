import ida_kernwin
import ida_idaapi
import ida_funcs


class JumpFuncStart_Handler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func:
            ida_kernwin.jumpto(func.start_ea)
            ida_kernwin.msg("Jumped to function start: 0x%X\n" % func.start_ea)
        else:
            ida_kernwin.msg("No function at current address.\n")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class JumpFuncStart_Plugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Jump to start of current function"
    help = "Jump to start of current function"
    wanted_name = "Jump to Func Start"
    wanted_hotkey = "Ctrl-Home"

    def init(self):
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func:
            ida_kernwin.jumpto(func.start_ea)
            ida_kernwin.msg("Jumped to function start: 0x%X\n" % func.start_ea)
        else:
            ida_kernwin.msg("No function at current address.\n")

    def term(self):
        pass


def PLUGIN_ENTRY():
    return JumpFuncStart_Plugin()