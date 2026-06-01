/*
 * (C) 2026 by sysmocom s.f.m.c. GmbH
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#define BUFFER_SIZE 8192

int main()
{
	int nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG);
	if (nl_fd < 0) {
		perror("Failed to open netlink socket.");
		return 1;
	}

	struct {
		struct nlmsghdr nlh;
		struct inet_diag_req_v2 req;
	} req;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct inet_diag_req_v2));
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;

	req.req.sdiag_family = AF_INET;
	req.req.sdiag_protocol = IPPROTO_SCTP;
	req.req.idiag_states = 0xFFFFFFFF;

	req.req.idiag_ext = (1 << (INET_DIAG_TOS - 1));

	if (send(nl_fd, &req, req.nlh.nlmsg_len, 0) < 0) {
		perror("Failed to sent netlink request.");
		close(nl_fd);
		return 1;
	}

	char buffer[BUFFER_SIZE];

	while (1) {
		ssize_t num_bytes = recv(nl_fd, buffer, sizeof(buffer), 0);
		if (num_bytes < 0) {
			perror("Failed to receive netlink response.");
			break;
		}

		struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
		while (NLMSG_OK(nlh, num_bytes)) {
			if (nlh->nlmsg_type == NLMSG_DONE) {
				close(nl_fd);
				return 0;
			}
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				perror("Netlink error received.");
				close(nl_fd);
				return 1;
			}

			struct inet_diag_msg *diag_msg = NLMSG_DATA(nlh);

			char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &diag_msg->id.idiag_src, src_ip, sizeof(src_ip));
			inet_ntop(AF_INET, &diag_msg->id.idiag_dst, dst_ip, sizeof(dst_ip));

			uint16_t src_port = ntohs(diag_msg->id.idiag_sport);
			uint16_t dst_port = ntohs(diag_msg->id.idiag_dport);

			char src_addr[32], dst_addr[32];
			snprintf(src_addr, sizeof(src_addr), "%s:%d", src_ip, src_port);
			snprintf(dst_addr, sizeof(dst_addr), "%s:%d", dst_ip, dst_port);

			const char *state_str = (diag_msg->idiag_state == TCP_ESTABLISHED) ? "ESTAB" :
						(diag_msg->idiag_state == TCP_LISTEN) ? "LISTEN" : "OTHER";

			uint8_t tos = 0;

			int rta_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct inet_diag_msg));
			struct rtattr *attr = (struct rtattr *)(diag_msg + 1);

			while (RTA_OK(attr, rta_len)) {
				if (attr->rta_type == INET_DIAG_TOS) {
					tos = *(uint8_t *)RTA_DATA(attr);
					break;
				}
				attr = RTA_NEXT(attr, rta_len);
			}

			/* state local remote dscp */
			printf("%s %s %s %d\n", state_str, src_addr, dst_addr, tos>>2);
			nlh = NLMSG_NEXT(nlh, num_bytes);
		}
	}

	close(nl_fd);
	return 0;
}
