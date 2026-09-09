import ida_kernwin
import ida_idaapi
import ida_funcs
import ea_tools_common as common


class CopyDeep_Handler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        top_func = ida_funcs.get_func(ea)

        if not top_func:
            ida_kernwin.msg("No function at current address.\n")
            return 1

        visited = {}          # func_start_ea -> call_path (list of names), first-discovered
        also_called_from = {} # func_start_ea -> set of caller names
        order = []            # order in which functions are discovered (DFS pre-order)

        top_name = common.get_func_name(top_func.start_ea)

        def dfs(func, call_path):
            fstart = func.start_ea
            if fstart in visited:
                # already dumped elsewhere; just note this caller
                if call_path:
                    also_called_from.setdefault(fstart, set()).add(call_path[-2] if len(call_path) > 1 else call_path[-1])
                return

            visited[fstart] = call_path
            order.append(fstart)

            call_targets = common.get_all_call_targets_in_function(func)
            for t in sorted(call_targets):
                callee = ida_funcs.get_func(t)
                if not callee:
                    continue
                if common.is_library_or_thunk(callee):
                    continue
                callee_name = common.get_func_name(callee.start_ea)
                dfs(callee, call_path + [callee_name])

        dfs(top_func, [top_name])

        # build output
        sections = []
        for i, fstart in enumerate(order):
            func = ida_funcs.get_func(fstart)
            fname = common.get_func_name(fstart)
            call_path = visited[fstart]
            path_str = " -> ".join(call_path)

            header = []
            header.append("; " + "=" * 50)
            top_tag = " [TOP LEVEL]" if fstart == top_func.start_ea else ""
            header.append("; Function @ 0x%X (%s)%s" % (fstart, fname, top_tag))
            header.append("; Call path: %s" % path_str)

            if fstart in also_called_from:
                extra = ", ".join(sorted(also_called_from[fstart]))
                header.append("; (Also called from: %s)" % extra)

            header.append("; " + "=" * 50)

            # for the top-level function, start dump from the cursor position;
            # for all others, dump from function start
            start_from = ea if fstart == top_func.start_ea else fstart
            body_lines = common.get_function_flat_lines(func, start_ea=start_from)

            sections.append("\n".join(header) + "\n" + "\n".join(body_lines))

        output_text = "\n\n".join(sections)

        path = common.save_text_to_file(output_text, "Save deep (recursive) dump as")
        if not path:
            ida_kernwin.msg("Save cancelled.\n")
            return 1

        ida_kernwin.msg("Saved %d function(s) to %s\n" % (len(order), path))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class CopyDeep_Plugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Recursively dump current function and all called functions to a text file"
    help = "Recursively dump current function and all called functions to a text file"
    wanted_name = "Copy Deep"
    wanted_hotkey = "Ctrl-Alt-N"

    def init(self):
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        CopyDeep_Handler().activate(None)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return CopyDeep_Plugin()