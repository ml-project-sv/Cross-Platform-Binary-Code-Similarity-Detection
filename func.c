void SSL_get0_next_proto_negotiated(const SSL *s, const unsigned char **data, unsigned *len)
{
    *data = s->next_proto_negotiated;
    if (func.cdata) {
        *len = 0;
    } else {
        *len = s->next_proto_negotiated_len;
    }
}
