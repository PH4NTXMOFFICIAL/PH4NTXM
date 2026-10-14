// Copyright (C) PH4NTXM
// Licensed under the GNU General Public License v3.0.

#include <usbguard/IPCClient.hpp>
#include <usbguard/Logger.hpp>
#include <usbguard/Rule.hpp>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <regex>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>
#include <unistd.h>

namespace {

constexpr std::size_t output_limit = 512 * 1024 - 1;
constexpr std::size_t identity_limit = 64 * 1024;
constexpr std::size_t device_limit = 512;
constexpr std::size_t interface_limit = 256;

struct GuardError : std::runtime_error {
    explicit GuardError(const char* code) : std::runtime_error(code) {}
};

class Json {
public:
    void append(const std::string& value)
    {
        if (value.size() > output_limit - data_.size()) {
            throw GuardError("metadata_limit");
        }
        data_ += value;
    }

    void string(const std::string& value)
    {
        static constexpr char hex[] = "0123456789abcdef";
        append("\"");
        for (std::size_t i = 0; i < value.size();) {
            const auto byte = static_cast<unsigned char>(value[i]);
            if (byte == '"' || byte == '\\') {
                append(std::string("\\") + static_cast<char>(byte));
                ++i;
            } else if (byte < 0x20 || byte == 0x7f) {
                std::string escaped = "\\u0000";
                escaped[4] = hex[byte >> 4];
                escaped[5] = hex[byte & 0x0f];
                append(escaped);
                ++i;
            } else if (byte < 0x80) {
                append(value.substr(i++, 1));
            } else {
                throw GuardError("invalid_metadata");
            }
        }
        append("\"");
    }

    void field(const char* name, const std::string& value)
    {
        string(name);
        append(":");
        string(value);
    }

    const std::string& value() const { return data_; }

private:
    std::string data_;
};

std::string single_string(const usbguard::Rule::Attribute<std::string>& attribute,
    std::size_t limit)
{
    if (attribute.count() > 1
        || attribute.setOperator() != usbguard::Rule::SetOperator::Equals) {
        throw GuardError("invalid_metadata");
    }
    const std::string value = attribute.empty() ? "" : attribute.get();
    if (value.size() > limit) {
        throw GuardError("metadata_limit");
    }
    return value;
}

std::string identity(const usbguard::Rule& rule)
{
    usbguard::Rule copy(rule);
    copy.setTarget(usbguard::Rule::Target::Device);
    const std::string value = copy.toString();
    if (value.empty() || value.size() > identity_limit) {
        throw GuardError("metadata_limit");
    }
    return value;
}

struct Device {
    std::uint32_t id;
    usbguard::Rule::Target target;
    std::string device_id;
    std::string name;
    std::string hash;
    std::string parent_hash;
    std::string port;
    std::string connect_type;
    std::string identity;
    std::vector<std::string> interfaces;
    std::string approval_reason;
};

Device describe(const usbguard::Rule& rule)
{
    Device device{};
    device.id = rule.getRuleID();
    device.target = rule.getTarget();
    if (device.target != usbguard::Rule::Target::Allow
        && device.target != usbguard::Rule::Target::Block
        && device.target != usbguard::Rule::Target::Reject) {
        throw GuardError("invalid_metadata");
    }
    if (device.id == usbguard::Rule::RootID
        || device.id == usbguard::Rule::DefaultID
        || device.id == usbguard::Rule::LastID
        || device.id == usbguard::Rule::ImplicitID
        || rule.attributeDeviceID().count() > 1
        || rule.attributeDeviceID().setOperator() != usbguard::Rule::SetOperator::Equals
        || !rule.attributeConditions().empty()
        || !rule.attributeLabel().empty()) {
        throw GuardError("invalid_metadata");
    }
    device.device_id = rule.attributeDeviceID().empty()
        ? "" : rule.getDeviceID().toRuleString();
    device.name = single_string(rule.attributeName(), 253);
    single_string(rule.attributeSerial(), 253);
    device.hash = single_string(rule.attributeHash(), 64);
    device.parent_hash = single_string(rule.attributeParentHash(), 64);
    device.port = single_string(rule.attributeViaPort(), 256);
    device.connect_type = single_string(rule.attributeWithConnectType(), 64);
    const auto& interfaces = rule.attributeWithInterface();
    if (interfaces.count() > interface_limit
        || interfaces.setOperator() != usbguard::Rule::SetOperator::Equals) {
        throw GuardError("invalid_metadata");
    }
    bool missing_interface = interfaces.empty();
    bool sensor = false;
    bool invalid_interface = false;
    static const std::regex interface_pattern("[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}");
    for (const auto& interface : interfaces.values()) {
        const std::string value = interface.typeString();
        device.interfaces.push_back(value);
        if (!std::regex_match(value, interface_pattern)) {
            invalid_interface = true;
            continue;
        }
        const auto interface_class = std::stoul(value.substr(0, 2), nullptr, 16);
        missing_interface = missing_interface || interface_class == 0;
        sensor = sensor || interface_class == 0x01 || interface_class == 0x0e || interface_class == 0x10;
    }
    device.identity = identity(rule);
    static const std::regex device_id_pattern("[0-9a-fA-F]{4}:[0-9a-fA-F]{4}");
    static const std::regex hash_pattern("[A-Za-z0-9+/]{43}=");
    static const std::regex root_port_pattern("usb[1-9][0-9]*");
    static const std::regex device_port_pattern("[1-9][0-9]*-[1-9][0-9]*(\\.[1-9][0-9]*)*");
    if (std::regex_match(device.port, root_port_pattern)) {
        device.approval_reason = "root_controller";
    } else if (!std::regex_match(device.device_id, device_id_pattern)
        || !std::regex_match(device.hash, hash_pattern)
        || !std::regex_match(device.port, device_port_pattern)
        || (!device.parent_hash.empty() && !std::regex_match(device.parent_hash, hash_pattern))) {
        device.approval_reason = "unavailable_identity";
    } else if (missing_interface || invalid_interface) {
        device.approval_reason = "unavailable_interfaces";
    } else if (sensor) {
        device.approval_reason = "sensor_device";
    } else if (device.target != usbguard::Rule::Target::Block) {
        device.approval_reason = "not_blocked";
    }
    return device;
}

std::vector<Device> describe_all(const std::vector<usbguard::Rule>& rules)
{
    if (rules.size() > device_limit) {
        throw GuardError("metadata_limit");
    }
    std::unordered_set<std::uint32_t> seen;
    std::vector<Device> devices;
    devices.reserve(rules.size());
    for (const auto& rule : rules) {
        auto device = describe(rule);
        if (!seen.insert(device.id).second) {
            throw GuardError("invalid_metadata");
        }
        devices.push_back(std::move(device));
    }
    return devices;
}

const Device& selected(const std::vector<Device>& devices, std::uint32_t id,
    const std::string& expected)
{
    for (const auto& device : devices) {
        if (device.id == id) {
            if (device.identity != expected) {
                throw GuardError("device_changed");
            }
            return device;
        }
    }
    throw GuardError("device_removed");
}

std::string hex_encode(const std::string& value)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string encoded;
    encoded.reserve(value.size() * 2);
    for (const unsigned char byte : value) {
        encoded += digits[byte >> 4];
        encoded += digits[byte & 0x0f];
    }
    return encoded;
}


std::string snapshot(const std::vector<Device>& devices,
    const std::string& inserted_policy, const std::string& implicit_target)
{
    if (inserted_policy.size() > 32 || implicit_target.size() > 32) {
        throw GuardError("invalid_metadata");
    }
    Json json;
    json.append("{\"ok\":true,");
    json.field("inserted_policy", inserted_policy);
    json.append(",");
    json.field("implicit_target", implicit_target);
    json.append(",\"devices\":[");
    bool first = true;
    for (const auto& device : devices) {
        if (!first) json.append(",");
        first = false;
        json.append("{\"id\":" + std::to_string(device.id) + ",");
        json.field("target", usbguard::Rule::targetToString(device.target));
        json.append(","); json.field("device_id", device.device_id);
        json.append(","); json.field("name_hex", hex_encode(device.name));
        json.append(","); json.field("hash", device.hash);
        json.append(","); json.field("parent_hash", device.parent_hash);
        json.append(","); json.field("port", device.port);
        json.append(","); json.field("connect_type", device.connect_type);
        json.append(","); json.field("identity_hex", hex_encode(device.identity));
        json.append(",\"interfaces\":[");
        bool first_interface = true;
        for (const auto& interface : device.interfaces) {
            if (!first_interface) json.append(",");
            first_interface = false;
            json.string(interface);
        }
        json.append("],\"approval_allowed\":");
        json.append(device.approval_reason.empty() ? "true" : "false");
        json.append(","); json.field("approval_reason", device.approval_reason);
        json.append("}");
    }
    json.append("]}");
    return json.value();
}

std::uint32_t parse_id(const std::string& value)
{
    if (value.empty() || value.size() > 10 || value[0] == '0') {
        throw GuardError("invalid_request");
    }
    std::uint64_t id = 0;
    for (const unsigned char byte : value) {
        if (byte < '0' || byte > '9') throw GuardError("invalid_request");
        id = id * 10 + (byte - '0');
        if (id > std::numeric_limits<std::uint32_t>::max()) {
            throw GuardError("invalid_request");
        }
    }
    return static_cast<std::uint32_t>(id);
}


std::string hex_decode(const std::string& encoded)
{
    if (encoded.empty() || encoded.size() > identity_limit * 2
        || encoded.size() % 2 != 0) {
        throw GuardError("invalid_request");
    }
    std::string decoded;
    decoded.reserve(encoded.size() / 2);
    unsigned char byte = 0;
    for (std::size_t i = 0; i < encoded.size(); ++i) {
        const char digit = encoded[i];
        unsigned char nibble = 0;
        if (digit >= '0' && digit <= '9') nibble = digit - '0';
        else if (digit >= 'a' && digit <= 'f') nibble = digit - 'a' + 10;
        else throw GuardError("invalid_request");
        byte = static_cast<unsigned char>((byte << 4) | nibble);
        if (i % 2) decoded += static_cast<char>(byte);
    }
    return decoded;
}

std::string read_identity()
{
    std::string encoded;
    char buffer[1024];
    constexpr std::size_t input_limit = identity_limit * 2 + 1;
    for (;;) {
        const ssize_t count = read(STDIN_FILENO, buffer, sizeof buffer);
        if (count < 0) {
            if (errno == EINTR) continue;
            throw GuardError("invalid_request");
        }
        if (count == 0) break;
        if (static_cast<std::size_t>(count) > input_limit - encoded.size()) {
            throw GuardError("invalid_request");
        }
        encoded.append(buffer, static_cast<std::size_t>(count));
    }
    if (!encoded.empty() && encoded.back() == '\n') encoded.pop_back();
    return hex_decode(encoded);
}

int run(int argc, char** argv)
{
    if (getuid() != 0 || geteuid() != 0) throw GuardError("permission_denied");
    if (argc < 2) throw GuardError("invalid_request");
    const std::string command = argv[1];
    const bool allow = command == "allow";
    if ((!allow && (command != "snapshot" || argc != 2))
        || (allow && argc != 3)) {
        throw GuardError("invalid_request");
    }
    const std::uint32_t id = allow ? parse_id(argv[2]) : 0;
    const std::string expected = allow ? read_identity() : "";
    usbguard::IPCClient client(true);
    const std::string inserted_policy = client.getParameter("InsertedDevicePolicy");
    const std::string implicit_target = client.getParameter("ImplicitPolicyTarget");
    auto devices = describe_all(client.listDevices());
    std::string result = snapshot(devices, inserted_policy, implicit_target);
    if (allow) {
        if (inserted_policy != "block" || implicit_target != "block") {
            throw GuardError("policy_changed");
        }
        const auto& before = selected(devices, id, expected);
        if (!before.approval_reason.empty()) throw GuardError("approval_unavailable");
        client.applyDevicePolicy(id, usbguard::Rule::Target::Allow, false);
        devices = describe_all(client.listDevices());
        if (selected(devices, id, expected).target != usbguard::Rule::Target::Allow) {
            throw GuardError("authorization_failed");
        }
        const auto inserted_after = client.getParameter("InsertedDevicePolicy");
        const auto implicit_after = client.getParameter("ImplicitPolicyTarget");
        if (inserted_after != "block" || implicit_after != "block") {
            throw GuardError("policy_changed");
        }
        result = snapshot(devices, inserted_after, implicit_after);
    }
    std::cout << result << '\n';
    return std::cout ? EXIT_SUCCESS : EXIT_FAILURE;
}

}

int main(int argc, char** argv)
{
    USBGUARD_LOGGER.setEnabled(false);
    try {
        return run(argc, argv);
    } catch (const GuardError& error) {
        std::cout << "{\"ok\":false,\"error\":\"" << error.what() << "\"}\n";
    } catch (...) {
        std::cout << "{\"ok\":false,\"error\":\"unavailable\"}\n";
    }
    return EXIT_FAILURE;
}
