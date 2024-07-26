@load base/protocols/ssl

event ssl_established(c: connection)
{
    if (|c$ssl$cert_chain| > 0)
    {
        local end_entity_cert = c$ssl$cert_chain[|c$ssl$cert_chain| - 1];

        if (end_entity_cert$x509$certificate$subject == end_entity_cert$x509$certificate$issuer)
        {
            print fmt("Self-signed certificate detected for %s", end_entity_cert$x509$certificate$subject);
        }
    }
}
