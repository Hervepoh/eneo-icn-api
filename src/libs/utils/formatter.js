"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseDMY = exports.getCurrentMonthYear = exports.formatDate = void 0;
exports.isEmpty = isEmpty;
function isEmpty(variable) {
    if (variable === null || variable === undefined || variable === '') {
        return true;
    }
    return false;
}
const formatDate = (value) => {
    const date = new Date(value);
    const month = date.getMonth() + 1; // Add 1 because month values are zero-based
    const day = date.getDate();
    const year = date.getFullYear();
    const formattedDate = `${day}/${month}/${year}`;
    return (formattedDate);
};
exports.formatDate = formatDate;
// Function to get the date in the format "MMYY"
const getCurrentMonthYear = (value) => {
    const currentDate = new Date(value);
    const month = String(currentDate.getMonth() + 1).padStart(2, '0');
    const year = String(currentDate.getFullYear()).slice(2);
    return `${month}${year}`;
};
exports.getCurrentMonthYear = getCurrentMonthYear;
const parseDMY = (s) => {
    let [d, m, y] = s.split(/\D/);
    return new Date(parseInt(y), parseInt(m) - 1, parseInt(d));
};
exports.parseDMY = parseDMY;
