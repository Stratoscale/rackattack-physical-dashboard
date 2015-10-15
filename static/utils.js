// There's no builtin solution for leading zeros
function padWithLeadingZeros(n) {
    return (n < 10) ? ("0" + n.toString()) : n.toString();
}
