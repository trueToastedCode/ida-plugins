import ida_funcs
import ida_gdl
import ida_xref
import ida_kernwin
import idc


def classify_successors(ea):
    """
    Returns (taken_list, fallthrough_list) of target addresses from
    the instruction at ea, based on code xref flow types.
    """
    xb = ida_xref.xrefblk_t()
    taken = []
    fallthrough = []

    ok = xb.first_from(ea, ida_xref.XREF_ALL)
    while ok:
        if xb.iscode:
            if xb.type in (ida_xref.fl_JN, ida_xref.fl_JF):
                taken.append(xb.to)
            elif xb.type == ida_xref.fl_F:
                fallthrough.append(xb.to)
        ok = xb.next_from()

    return taken, fallthrough


def get_call_targets(ea):
    """
    Returns a list of function-start addresses that are directly called
    (fl_CN / fl_CF) from the instruction at ea.
    """
    xb = ida_xref.xrefblk_t()
    targets = []

    ok = xb.first_from(ea, ida_xref.XREF_ALL)
    while ok:
        if xb.iscode and xb.type in (ida_xref.fl_CN, ida_xref.fl_CF):
            targets.append(xb.to)
        ok = xb.next_from()

    return targets


def is_library_or_thunk(func):
    """
    Returns True if the function is a library function or a thunk
    (i.e. not real user code we want to recurse into).
    """
    flags = func.flags
    return bool(flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK))


def get_func_name(ea):
    name = idc.get_func_name(ea)
    return name if name else ("sub_%X" % ea)


def get_function_flat_lines(func, start_ea=None):
    """
    Returns a list of text lines representing the flattened,
    branch-annotated disassembly of `func`, starting from `start_ea`
    (or the function start if not given), walking reachable blocks
    only (no call-following).
    """
    flowchart = ida_gdl.FlowChart(func)

    if start_ea is None:
        start_ea = func.start_ea

    start_block = None
    for block in flowchart:
        if block.start_ea <= start_ea < block.end_ea:
            start_block = block
            break

    if start_block is None:
        return ["; (could not resolve starting block)"]

    visited = set()
    queue = [start_block]
    reachable_blocks = []

    while queue:
        blk = queue.pop(0)
        if blk.start_ea in visited:
            continue
        visited.add(blk.start_ea)
        reachable_blocks.append(blk)
        for succ in blk.succs():
            if succ.start_ea not in visited:
                queue.append(succ)

    reachable_blocks.sort(key=lambda b: b.start_ea)

    lines = []
    for blk in reachable_blocks:
        lines.append("; --- Block @ 0x%X ---" % blk.start_ea)
        cur = blk.start_ea
        last_ea = None
        while cur < blk.end_ea:
            disasm = idc.generate_disasm_line(cur, 0)
            lines.append("%08X  %s" % (cur, disasm))
            last_ea = cur
            cur = idc.next_head(cur, blk.end_ea)

        if last_ea is not None:
            taken, fallthrough = classify_successors(last_ea)
            for t in taken:
                lines.append("%*s; [True/Take] -> 0x%X" % (10, "", t))
            for f in fallthrough:
                lines.append("%*s; [False/Fall] -> 0x%X" % (10, "", f))

        lines.append("")

    return lines


def get_all_call_targets_in_function(func):
    """
    Returns a set of function-start addresses called anywhere inside `func`
    (only within reachable code, scanning every instruction in the function).
    """
    targets = set()
    ea = func.start_ea
    while ea < func.end_ea and ea != idc.BADADDR:
        for t in get_call_targets(ea):
            callee = ida_funcs.get_func(t)
            if callee:
                targets.add(callee.start_ea)
        ea = idc.next_head(ea, func.end_ea)
    return targets


def save_text_to_file(text, title="Save output as"):
    path = ida_kernwin.ask_file(1, "*.txt", title)
    if not path:
        return None
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path