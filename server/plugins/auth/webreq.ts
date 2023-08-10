import colors from "chalk";
import log from "../../log";
import Helper from "../../helper";
import type {AuthHandler} from "../auth";
import axios from "axios";
import config from "../../config";

// eslint-disable-next-line @typescript-eslint/no-misused-promises
const webreqAuth: AuthHandler = async (manager, client, user, password, callback) => {
	// If no user is found, or if the client has not provided a password,
	// fail the authentication straight away
	if (!client || !password) {
		return callback(false);
	}

	const values = config.values.webreq;
	FormData;
	const res = await axios({
		url: values.url,
		method: values.method,
		data: values.body
			.replaceAll("$username", user.toLowerCase())
			.replace("$password", password),
	});
	console.log(
		values.body.replaceAll("$username", user.toLowerCase()).replace("$password", password)
	);
	console.log(res.data);

	if (res.data == values.authorisedResponse) {
		log.info(`User ${colors.bold(client.name)} logged in through webreq`);
		return callback(true);
	} else if (!values.checkpassword) {
		return callback(false);
	}

	// If this user has no password set, fail the authentication
	if (!client.config.password) {
		log.error(
			`User ${colors.bold(
				user
			)} with no local password set tried to sign in. (Probably a LDAP user)`
		);
		return callback(false);
	}

	Helper.password
		.compare(password, client.config.password)
		.then((matching) => {
			if (matching && Helper.password.requiresUpdate(client.config.password)) {
				const hash = Helper.password.hash(password);

				client.setPassword(hash, (success) => {
					if (success) {
						log.info(
							`User ${colors.bold(
								client.name
							)} logged in and their hashed password has been updated to match new security requirements`
						);
					}
				});
			}

			callback(matching);
		})
		.catch((error) => {
			// eslint-disable-next-line @typescript-eslint/restrict-template-expressions
			log.error(`Error while checking users password. Error: ${error}`);
		});
};

export default {
	moduleName: "local",
	auth: webreqAuth,
	isEnabled: () => config.values?.webreq?.enable,
};
