"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.serviceType = exports.NotificationType = exports.EventType = void 0;
var EventType;
(function (EventType) {
    EventType["LOGIN"] = "LOGIN";
    EventType["LOGOUT"] = "LOGOUT";
})(EventType || (exports.EventType = EventType = {}));
var NotificationType;
(function (NotificationType) {
    NotificationType["EMAIL"] = "EMAIL";
    NotificationType["WHATSAPP"] = "WHATSAPP";
})(NotificationType || (exports.NotificationType = NotificationType = {}));
var serviceType;
(function (serviceType) {
    serviceType["SUMMARY"] = "SUMMARY";
    serviceType["TRANSACTION"] = "TRANSACTION";
    serviceType["PAYMENTMODE"] = "PAYMENTMODE";
    serviceType["BANK"] = "BANK";
    serviceType["ICN"] = "ICN";
    serviceType["UNPAID"] = "UNPAID";
    serviceType["ROLE"] = "ROLE";
    serviceType["PERMISSION"] = "PERMISSION";
    serviceType["NOTIFICATION"] = "NOTIFICATION";
})(serviceType || (exports.serviceType = serviceType = {}));
