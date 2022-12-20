#include <iterator>
#include <regex>
#include <fstream>
#include <variant>
#include <sstream>
#include <map>
#include <span>

#include <boost/variant.hpp>

#include "../../include/dbcppp/Network.h"
#include "../../include/dbcppp/CApi.h"

#include "DBCX3.h"

using namespace dbcppp;
using namespace dbcppp::DBCX3::AST;


struct NetIndex
{
    explicit NetIndex(const G_Network& gnet)
    {
        for (size_t i = 0; i < gnet.attribute_values.size(); ++i)
        {
            const auto& c = gnet.attribute_values[i];
            if (auto p = boost::get<G_AttributeNode>(&c))
                attribute_nodes[p->node_name].emplace_back(p);
            else if (auto p = boost::get<G_AttributeSignal>(&c))
                attribute_signals[AttributeSignalKey{ p->message_id, p->signal_name }].emplace_back(p);
            else if (auto p = boost::get<G_AttributeMessage>(&c))
                attribute_messages[p->message_id].emplace_back(p);
            else if (auto p = boost::get<G_AttributeEnvVar>(&c))
                attribute_env_vars[p->env_var_name].emplace_back(p);
        }

        for (size_t i = 0; i < gnet.value_descriptions_sig_env_var.size(); ++i)
        {
            const auto& c = gnet.value_descriptions_sig_env_var[i];
            if (auto p = boost::get<G_ValueDescriptionSignal>(&c.description))
                value_description_signals[ValueDescriptionSignalKey{ p->message_id, p->signal_name }] = p;
            else if (auto p = boost::get<G_ValueDescriptionEnvVar>(&c.description))
                value_description_env_vars[p->env_var_name] = p;
        }

        for (size_t i = 0; i < gnet.comments.size(); ++i)
        {
            const auto& c = gnet.comments[i];
            if (auto p = boost::get<G_CommentSignal>(&c.comment))
                comment_signals[CommentSignalKey{ p->message_id, p->signal_name }] = p;
            else if (auto p = boost::get<G_CommentNode>(&c.comment))
                comment_nodes[p->node_name] = p;
            else if (auto p = boost::get<G_CommentMessage>(&c.comment))
                comment_messages[p->message_id] = p;
            else if (auto p = boost::get<G_CommentEnvVar>(&c.comment))
                comment_env_vars[p->env_var_name] = p;
        }

        for (size_t i = 0; i < gnet.signal_extended_value_types.size(); ++i)
        {
            const auto& c = gnet.signal_extended_value_types[i];
            signal_extended_value_types[SignalExtendedValueTypeKey{ c.message_id, c.signal_name }] = &c;
        }

        for (size_t i = 0; i < gnet.signal_multiplexer_values.size(); ++i)
        {
            const auto& c = gnet.signal_multiplexer_values[i];
            signal_multiplexer_values[SignalMultiplexerValueKey{ c.message_id, c.signal_name }].emplace_back(&c);
        }

        for (size_t i = 0; i < gnet.message_transmitters.size(); ++i)
        {
            const auto& c = gnet.message_transmitters[i];
            message_transmitters[c.id] = &c;
        }

        for (size_t i = 0; i < gnet.signal_groups.size(); ++i)
        {
            const auto& c = gnet.signal_groups[i];
            signal_groups[c.message_id].emplace_back(&c);
        }
    }

    using AttributeNodeKey = std::string;
    std::map<AttributeNodeKey, std::vector<const G_AttributeNode*>> attribute_nodes;

    using AttributeSignalKey = std::pair<uint64_t, std::string>;
    std::map<AttributeSignalKey, std::vector<const G_AttributeSignal*>> attribute_signals;

    using ValueDescriptionSignalKey = std::pair<uint64_t, std::string>;
    std::map<ValueDescriptionSignalKey, const G_ValueDescriptionSignal*> value_description_signals;

    using CommentSignalKey = std::pair<uint64_t, std::string>;
    std::map<CommentSignalKey, const G_CommentSignal*> comment_signals;

    using CommentNodeKey = std::string;
    std::map<CommentNodeKey, const G_CommentNode*> comment_nodes;

    using SignalExtendedValueTypeKey = std::pair<uint64_t, std::string>;
    std::map<SignalExtendedValueTypeKey, const G_SignalExtendedValueType*> signal_extended_value_types;

    using SignalMultiplexerValueKey = std::pair<uint64_t, std::string>;
    std::map<SignalMultiplexerValueKey, std::vector<const G_SignalMultiplexerValue*>> signal_multiplexer_values;

    using MessageTransmitterKey = uint64_t;
    std::map<MessageTransmitterKey, const G_MessageTransmitter*> message_transmitters;

    using AttributeMessageKey = uint64_t;
    std::map<AttributeMessageKey, std::vector<const G_AttributeMessage*>> attribute_messages;

    using CommentMessageKey = uint64_t;
    std::map<CommentMessageKey, const G_CommentMessage*> comment_messages;

    using SignalGroupKey = uint64_t;
    std::map<SignalGroupKey, std::vector<const G_SignalGroup*>> signal_groups;

    using ValueDescriptionEnvVarKey = std::string;
    std::map<ValueDescriptionEnvVarKey, const G_ValueDescriptionEnvVar*> value_description_env_vars;

    using AttributeEnvVarKey = std::string;
    std::map<AttributeEnvVarKey, std::vector<const G_AttributeEnvVar*>> attribute_env_vars;

    using CommentEnvVarKey = std::string;
    std::map<CommentEnvVarKey, const G_CommentEnvVar*> comment_env_vars;
};

template<typename K, typename T>
std::span<T const* const> ni_find(const std::map<K, std::vector<const T*>>& m, const K& key)
{
    auto it = m.find(key);
    if (it == m.end())
        return {};
    return std::span<T const* const>(it->second.data(), it->second.size());
}

template<typename K, typename T>
const T* ni_find(const std::map<K, const T*>& m, const K& key)
{
    auto it = m.find(key);
    if (it == m.end())
        return nullptr;
    return it->second;
}

static auto getVersion(const G_Network& gnet)
{
    return gnet.version.version;
}
static auto getNewSymbols(const G_Network& gnet)
{
    std::vector<std::string> nodes;
    for (const auto& ns : gnet.new_symbols)
    {
        nodes.push_back(ns);
    }
    return nodes;
}
static auto getSignalType(const G_Network& gnet, const G_ValueTable& vt)
{
    std::optional<std::unique_ptr<ISignalType>> signal_type;
    auto iter = std::find_if(gnet.signal_types.begin(), gnet.signal_types.end(),
        [&](const auto& st)
        {
            return st.value_table_name == vt.name;
        });
    if (iter != gnet.signal_types.end())
    {
        auto& st = *iter;
        signal_type = ISignalType::Create(
              std::string(st.name)
            , st.size
            , st.byte_order == '0' ? ISignal::EByteOrder::BigEndian : ISignal::EByteOrder::LittleEndian
            , st.value_type == '+' ? ISignal::EValueType::Unsigned : ISignal::EValueType::Signed
            , st.factor
            , st.offset
            , st.minimum
            , st.maximum
            , std::string(st.unit)
            , st.default_value
            , std::string(st.value_table_name));
    }
    return signal_type;
}
static auto getValueTables(const G_Network& gnet)
{
    std::vector<std::unique_ptr<IValueTable>> value_tables;
    for (const auto& vt : gnet.value_tables)
    {
        auto sig_type = getSignalType(gnet, vt);
        std::vector<std::unique_ptr<IValueEncodingDescription>> copy_ved;
        for (const auto& ved : vt.value_encoding_descriptions)
        {
            auto desc = ved.description;
            auto pved = IValueEncodingDescription::Create(ved.value, std::move(desc));
            copy_ved.push_back(std::move(pved));
        }
        auto nvt = IValueTable::Create(std::string(vt.name), std::move(sig_type), std::move(copy_ved));
        value_tables.push_back(std::move(nvt));
    }
    return value_tables;
}
static auto getBitTiming(const G_Network& gnet)
{
    std::unique_ptr<IBitTiming> bit_timing;
    if (gnet.bit_timing)
    {
        bit_timing = IBitTiming::Create(gnet.bit_timing->baudrate, gnet.bit_timing->BTR1, gnet.bit_timing->BTR2);
    }
    else
    {
        bit_timing = IBitTiming::Create(0, 0, 0);
    }
    return bit_timing;
}

#if 0
template <class Variant>
class Visitor
    : public boost::static_visitor<void>
{
public:
    Visitor(Variant& var)
        : _var(var)
    {}
    template <class T>
    void operator()(const T& v)
    {
        _var = v;
    }

private:
    Variant& _var;
};

template <class... Args>
auto boost_variant_to_std_variant(const boost::variant<Args...>& old)
{
    using var_t = std::variant<Args...>;
    var_t new_;
    Visitor<var_t> visitor(new_);
    old.apply_visitor(visitor);
    return new_;
}
#endif

static auto getAttributeValues(std::span<G_AttributeNode const* const> pp)
{
    std::vector<std::unique_ptr<IAttribute>> attribute_values;
    attribute_values.reserve(pp.size());
    for (const G_AttributeNode* p : pp)
    {
        auto attribute = IAttribute::Create(std::string(p->attribute_name), IAttributeDefinition::EObjectType::Node, p->value);
        attribute_values.push_back(std::move(attribute));
    }
    return attribute_values;
}
static auto getComment(const G_CommentNode* p)
{
    std::string comment;
    if (p)
    {
        comment = p->comment;
    }
    return comment;
}
static auto getNodes(const G_Network& gnet, const NetIndex& ni)
{
    std::vector<std::unique_ptr<INode>> nodes;
    for (const auto& n : gnet.nodes)
    {
        auto comment = getComment(ni_find(ni.comment_nodes, n.name));
        auto attribute_values = getAttributeValues(ni_find(ni.attribute_nodes, n.name));
        auto nn = INode::Create(std::string(n.name), std::move(comment), std::move(attribute_values));
        nodes.push_back(std::move(nn));
    }
    return nodes;
}
static auto getAttributeValues(std::span<G_AttributeSignal const* const> pp)
{
    std::vector<std::unique_ptr<IAttribute>> attribute_values;
    attribute_values.reserve(pp.size());
    for (const G_AttributeSignal* p : pp)
    {
        auto attribute = IAttribute::Create(std::string(p->attribute_name), IAttributeDefinition::EObjectType::Signal, p->value);
        attribute_values.push_back(std::move(attribute));
    }
    return attribute_values;
}
static auto getValueDescriptions(const G_ValueDescriptionSignal* p)
{
    std::vector<std::unique_ptr<IValueEncodingDescription>> value_descriptions;
    if(p)
	{
        value_descriptions.reserve(p->value_descriptions.size());
        for (const auto& vd : p->value_descriptions)
        {
            auto desc = vd.description;
            auto pvd = IValueEncodingDescription::Create(vd.value, std::move(desc));
            value_descriptions.push_back(std::move(pvd));
        }
    }
    return value_descriptions;
}
static auto getComment(const G_CommentSignal* p)
{
    std::string comment;
    if (p)
    {
        comment = p->comment;
    }
    return comment;
}
static auto getSignalExtendedValueType(const G_SignalExtendedValueType* p)
{
    ISignal::EExtendedValueType extended_value_type = ISignal::EExtendedValueType::Integer;
    if (p)
    {
        switch (p->value)
        {
        case 1: extended_value_type = ISignal::EExtendedValueType::Float; break;
        case 2: extended_value_type = ISignal::EExtendedValueType::Double; break;
        }
    }
    return extended_value_type;
}
static auto getSignalMultiplexerValues(std::span<G_SignalMultiplexerValue const* const> pp)
{
    std::vector<std::unique_ptr<ISignalMultiplexerValue>> signal_multiplexer_values;
    signal_multiplexer_values.reserve(pp.size());
    for (const G_SignalMultiplexerValue* p : pp)
    {
        auto switch_name = p->switch_name;
        std::vector<ISignalMultiplexerValue::Range> value_ranges;
        for (const auto& r : p->value_ranges)
        {
            value_ranges.push_back({ r.from, r.to });
        }
        auto signal_multiplexer_value = ISignalMultiplexerValue::Create(
            std::move(switch_name)
            , std::move(value_ranges));
        signal_multiplexer_values.push_back(std::move(signal_multiplexer_value));
    }
    return signal_multiplexer_values;
}

static auto getSignals(const G_Network& gnet, const G_Message& m, const NetIndex& ni)
{
    std::vector<std::unique_ptr<ISignal>> signals;
    for (const G_Signal& s : m.signals)
    {
        std::vector<std::string> receivers;
        auto attribute_values = getAttributeValues(ni_find(ni.attribute_signals, { m.id, s.name }));
        auto value_descriptions = getValueDescriptions(ni_find(ni.value_description_signals, { m.id, s.name }));
        auto extended_value_type = getSignalExtendedValueType(ni_find(ni.signal_extended_value_types, { m.id, s.name }));
        auto multiplexer_indicator = ISignal::EMultiplexer::NoMux;
        auto comment = getComment(ni_find(ni.comment_signals, { m.id, s.name }));
        auto signal_multiplexer_values = getSignalMultiplexerValues(ni_find(ni.signal_multiplexer_values, { m.id, s.name }));
        uint64_t multiplexer_switch_value = 0;
        if (s.multiplexer_indicator)
        {
            auto m = *s.multiplexer_indicator;
            if (m.substr(0, 1) == "M")
            {
                multiplexer_indicator = ISignal::EMultiplexer::MuxSwitch;
            }
            else
            {
                multiplexer_indicator = ISignal::EMultiplexer::MuxValue;
                std::string value = m.substr(1, m.size());
                multiplexer_switch_value = std::atoi(value.c_str());
            }
        }
        for (const auto& n : s.receivers)
        {
            receivers.push_back(n);
        }

        auto ns = ISignal::Create(
              m.size
            , std::string(s.name)
            , multiplexer_indicator
            , multiplexer_switch_value
            , s.start_bit
            , s.signal_size
            , s.byte_order == '0' ? ISignal::EByteOrder::BigEndian : ISignal::EByteOrder::LittleEndian
            , s.value_type == '+' ? ISignal::EValueType::Unsigned : ISignal::EValueType::Signed
            , s.factor
            , s.offset
            , s.minimum
            , s.maximum
            , std::string(s.unit)
            , std::move(receivers)
            , std::move(attribute_values)
            , std::move(value_descriptions)
            , std::move(comment)
            , extended_value_type
            , std::move(signal_multiplexer_values));
        if (ns->Error(ISignal::EErrorCode::SignalExceedsMessageSize))
        {
            std::cout << "Warning: The signals '" << m.name << "::" << s.name << "'"
                << " start_bit + bit_size exceeds the byte size of the message! Ignoring this error will lead to garbage data when using the decode function of this signal." << std::endl;
        }
        if (ns->Error(ISignal::EErrorCode::WrongBitSizeForExtendedDataType))
        {
            std::cout << "Warning: The signals '" << m.name << "::" << s.name << "'"
                << " bit_size does not fit the bit size of the specified ExtendedValueType." << std::endl;
        }
        if (ns->Error(ISignal::EErrorCode::MaschinesFloatEncodingNotSupported))
        {
            std::cout << "Warning: Signal '" << m.name << "::" << s.name << "'"
                << " This warning appears when a signal uses type float but the system this programm is running on does not uses IEEE 754 encoding for floats." << std::endl;
        }
        if (ns->Error(ISignal::EErrorCode::MaschinesDoubleEncodingNotSupported))
        {
            std::cout << "Warning: Signal '" << m.name << "::" << s.name << "'"
                << " This warning appears when a signal uses type double but the system this programm is running on does not uses IEEE 754 encoding for doubles." << std::endl;
        }
        signals.push_back(std::move(ns));
    }
    return signals;
}
static auto getMessageTransmitters(const G_MessageTransmitter* p)
{
    std::vector<std::string> message_transmitters;
    if (p)
    {
        message_transmitters.reserve(p->transmitters.size());
        for (const auto& t : p->transmitters)
        {
            message_transmitters.push_back(t);
        }
    }
    return message_transmitters;
}
static auto getAttributeValues(std::span<G_AttributeMessage const* const> pp)
{
    std::vector<std::unique_ptr<IAttribute>> attribute_values;
    attribute_values.reserve(pp.size());
    for (const G_AttributeMessage* p : pp)
    {
        auto attribute = IAttribute::Create(std::string(p->attribute_name), IAttributeDefinition::EObjectType::Message, p->value);
        attribute_values.push_back(std::move(attribute));
    }
    return attribute_values;
}
static auto getComment(const G_CommentMessage* p)
{
    std::string comment;
    if (p)
    {
        comment = p->comment;
    }
    return comment;
}
static auto getSignalGroups(std::span<G_SignalGroup const* const> pp)
{
    std::vector<std::unique_ptr<ISignalGroup>> signal_groups;
    signal_groups.reserve(pp.size());
    for (const G_SignalGroup* p : pp)
    {
        auto name = p->signal_group_name;
        auto signal_names = p->signal_names;
        auto signal_group = ISignalGroup::Create(
            p->message_id
            , std::move(name)
            , p->repetitions
            , std::move(signal_names));
        signal_groups.push_back(std::move(signal_group));
    }
    return signal_groups;
}
static auto getMessages(const G_Network& gnet, const NetIndex& ni)
{
    std::vector<std::unique_ptr<IMessage>> messages;
    for (const auto& m : gnet.messages)
    {
        auto message_transmitters = getMessageTransmitters(ni_find(ni.message_transmitters, m.id));
        auto signals = getSignals(gnet, m, ni);
        auto attribute_values = getAttributeValues(ni_find(ni.attribute_messages, m.id));
        auto comment = getComment(ni_find(ni.comment_messages, m.id));
        auto signal_groups = getSignalGroups(ni_find(ni.signal_groups, m.id));
        auto msg = IMessage::Create(
              m.id
            , std::string(m.name)
            , m.size
            , std::string(m.transmitter)
            , std::move(message_transmitters)
            , std::move(signals)
            , std::move(attribute_values)
            , std::move(comment)
            , std::move(signal_groups));
        if (msg->Error() == IMessage::EErrorCode::MuxValeWithoutMuxSignal)
        {
            std::cout << "Warning: Message " << msg->Name() << " does have mux value but no mux signal!" << std::endl;
        }
        messages.push_back(std::move(msg));
    }
    return messages;
}
static auto getValueDescriptions(const G_ValueDescriptionEnvVar* p)
{
    std::vector<std::unique_ptr<IValueEncodingDescription>> value_descriptions;
    if (p)
    {
        value_descriptions.reserve(p->value_descriptions.size());
        for (const auto& vd : p->value_descriptions)
        {
            auto desc = vd.description;
            auto pvd = IValueEncodingDescription::Create(vd.value, std::move(desc));
            value_descriptions.push_back(std::move(pvd));
        }
    }
    return value_descriptions;
}
static auto getAttributeValues(std::span<G_AttributeEnvVar const* const> pp)
{
    std::vector<std::unique_ptr<IAttribute>> attribute_values;
    attribute_values.reserve(pp.size());
    for (const G_AttributeEnvVar* p : pp)
    {
        auto attribute = IAttribute::Create(std::string(p->attribute_name), IAttributeDefinition::EObjectType::EnvironmentVariable, p->value);
        attribute_values.push_back(std::move(attribute));
    }
    return attribute_values;
}
static auto getComment(const G_CommentEnvVar* p)
{
    std::string comment;
    if (p)
    {
        comment = p->comment;
    }
    return comment;
}
static auto getEnvironmentVariables(const G_Network& gnet, const NetIndex& ni)
{
    std::vector<std::unique_ptr<IEnvironmentVariable>> environment_variables;
    for (const auto& ev : gnet.environment_variables)
    {
        IEnvironmentVariable::EVarType var_type;
        IEnvironmentVariable::EAccessType access_type;
        std::vector<std::string> access_nodes = ev.access_nodes;
        auto value_descriptions = getValueDescriptions(ni_find(ni.value_description_env_vars, ev.name));
        auto attribute_values = getAttributeValues(ni_find(ni.attribute_env_vars, ev.name));
        auto comment = getComment(ni_find(ni.comment_env_vars, ev.name));
        uint64_t data_size = 0;
        switch (ev.var_type)
        {
        case 0: var_type = IEnvironmentVariable::EVarType::Integer; break;
        case 1: var_type = IEnvironmentVariable::EVarType::Float; break;
        case 2: var_type = IEnvironmentVariable::EVarType::String; break;
        }
        access_type = IEnvironmentVariable::EAccessType::Unrestricted;
        if (ev.access_type == "DUMMY_NODE_VECTOR0")         access_type = IEnvironmentVariable::EAccessType::Unrestricted;
        else if (ev.access_type == "DUMMY_NODE_VECTOR1")    access_type = IEnvironmentVariable::EAccessType::Read;
        else if (ev.access_type == "DUMMY_NODE_VECTOR2")    access_type = IEnvironmentVariable::EAccessType::Write;
        else if (ev.access_type == "DUMMY_NODE_VECTOR3")    access_type = IEnvironmentVariable::EAccessType::ReadWrite;
        else if (ev.access_type == "DUMMY_NODE_VECTOR8000") access_type = IEnvironmentVariable::EAccessType::Unrestricted_;
        else if (ev.access_type == "DUMMY_NODE_VECTOR8001") access_type = IEnvironmentVariable::EAccessType::Read_;
        else if (ev.access_type == "DUMMY_NODE_VECTOR8002") access_type = IEnvironmentVariable::EAccessType::Write_;
        else if (ev.access_type == "DUMMY_NODE_VECTOR8003") access_type = IEnvironmentVariable::EAccessType::ReadWrite_;
        for (auto& evd : gnet.environment_variable_datas)
        {
            if (evd.name == ev.name)
            {
                var_type = IEnvironmentVariable::EVarType::Data;
                data_size = evd.size;
                break;
            }
        }
        auto env_var = IEnvironmentVariable::Create(
              std::string(ev.name)
            , var_type
            , ev.minimum
            , ev.maximum
            , std::string(ev.unit)
            , ev.initial_value
            , ev.id
            , access_type
            , std::move(access_nodes)
            , std::move(value_descriptions)
            , data_size
            , std::move(attribute_values)
            , std::move(comment));
        environment_variables.push_back(std::move(env_var));
    }
    return environment_variables;
}
static auto getAttributeDefinitions(const G_Network& gnet)
{
    std::vector<std::unique_ptr<IAttributeDefinition>> attribute_definitions;
    struct VisitorValueType
    {
        IAttributeDefinition::value_type_t operator()(const G_AttributeValueTypeInt& cn)
        {
            IAttributeDefinition::ValueTypeInt vt;
            vt.minimum = cn.minimum;
            vt.maximum = cn.maximum;
            return vt;
        }
        IAttributeDefinition::value_type_t operator()(const G_AttributeValueTypeHex& cn)
        {
            IAttributeDefinition::ValueTypeHex vt;
            vt.minimum = cn.minimum;
            vt.maximum = cn.maximum;
            return vt;
        }
        IAttributeDefinition::value_type_t operator()(const G_AttributeValueTypeFloat& cn)
        {
            IAttributeDefinition::ValueTypeFloat vt;
            vt.minimum = cn.minimum;
            vt.maximum = cn.maximum;
            return vt;
        }
        IAttributeDefinition::value_type_t operator()(const G_AttributeValueTypeString& cn)
        {
            return IAttributeDefinition::ValueTypeString();
        }
        IAttributeDefinition::value_type_t operator()(const G_AttributeValueTypeEnum& cn)
        {
            IAttributeDefinition::ValueTypeEnum vt;
            for (auto& e : cn.values)
            {
                vt.values.emplace_back(e);
            }
            return vt;
        }
    };
    for (const auto& ad : gnet.attribute_definitions)
    {
        IAttributeDefinition::EObjectType object_type;
        auto cvt = ad.value_type;
        if (!ad.object_type)
        {
            object_type = IAttributeDefinition::EObjectType::Network;
        }
        else if (*ad.object_type == "BU_")
        {
            object_type = IAttributeDefinition::EObjectType::Node;
        }
        else if (*ad.object_type == "BO_")
        {
            object_type = IAttributeDefinition::EObjectType::Message;
        }
        else if (*ad.object_type == "SG_")
        {
            object_type = IAttributeDefinition::EObjectType::Signal;
        }
        else
        {
            object_type = IAttributeDefinition::EObjectType::EnvironmentVariable;
        }
        VisitorValueType vvt;
        auto nad = IAttributeDefinition::Create(std::move(std::string(ad.name)), object_type, boost::apply_visitor(vvt, cvt.value));
        attribute_definitions.push_back(std::move(nad));
    }
    return attribute_definitions;
}
static auto getAttributeDefaults(const G_Network& gnet)
{
    std::vector<std::unique_ptr<IAttribute>> attribute_defaults;
    for (auto& ad : gnet.attribute_defaults)
    {
        auto nad = IAttribute::Create(std::string(ad.name), IAttributeDefinition::EObjectType::Network, ad.value);
        attribute_defaults.push_back(std::move(nad));
    }
    return attribute_defaults;
}
static auto getAttributeValues(const G_Network& gnet)
{
    std::vector<std::unique_ptr<IAttribute>> attribute_values;
    for (const auto& av : gnet.attribute_values)
    {
        if (auto pan = boost::get<G_AttributeNetwork>(&av))
        {
            auto av_ = *pan;
            auto attribute = IAttribute::Create(
                std::string(av_.attribute_name)
                , IAttributeDefinition::EObjectType::Network
                , av_.value);
            attribute_values.push_back(std::move(attribute));
        }
    }
    return attribute_values;
}
static auto getComment(const G_Network& gnet)
{
    std::string comment;
    for (const auto& c : gnet.comments)
    {
        if (auto pcn = boost::get<G_CommentNetwork>(&c.comment))
        {
            comment = pcn->comment;
            break;
        }
    }
    return comment;
}

std::unique_ptr<INetwork> DBCAST2Network(const G_Network& gnet)
{
    NetIndex ni { gnet };

    return INetwork::Create(
          getVersion(gnet)
        , getNewSymbols(gnet)
        , getBitTiming(gnet)
        , getNodes(gnet, ni)
        , getValueTables(gnet)
        , getMessages(gnet, ni)
        , getEnvironmentVariables(gnet, ni)
        , getAttributeDefinitions(gnet)
        , getAttributeDefaults(gnet)
        , getAttributeValues(gnet)
        , getComment(gnet));
}

std::unique_ptr<INetwork> INetwork::LoadDBCFromIs(std::istream& is)
{
    std::string str((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
    std::unique_ptr<dbcppp::INetwork> network;
    if (auto gnet = dbcppp::DBCX3::ParseFromMemory(str.c_str(), str.c_str() + str.size()))
    {
        network = DBCAST2Network(*gnet);
    }
    return network;
}
extern "C"
{
    DBCPPP_API const dbcppp_Network* dbcppp_NetworkLoadDBCFromFile(const char* filename)
    {
        std::ifstream is(filename);
        auto net = INetwork::LoadDBCFromIs(is);
        return reinterpret_cast<const dbcppp_Network*>(net.release());
    }
    DBCPPP_API const dbcppp_Network* dbcppp_NetworkLoadDBCFromMemory(const char* data)
    {
        std::istringstream iss(data);
        auto net = INetwork::LoadDBCFromIs(iss);
        return reinterpret_cast<const dbcppp_Network*>(net.release());
    }
}