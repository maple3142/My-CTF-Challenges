from Crypto.Cipher import ARC4
from base64 import b64encode

flags = [
	'jctf{red_flags_and_fake_flags_form_an_equivalence_class}',
	'jctf{just_cat_the_fish}',
	'jctf{sourcelesswebaphobia}',
	'jctf{making_fake_flags_is_more_fun_than_making_real_flags}',
	'jctf{never_gonna_give_you_up}',
	'jctf{never_gonna_let_you_down}',
	'jctf{what_even_is_an_equivalence_class}',
	'jctf{%s}',
	'jctf{s3cr3t_fl4g_generated_by_ChatGPT}',
	'jctf{<script>alert("xss")</script>}',
	'jctf{watch_me_put_an_emote_in_a_flag_to_screw_nitro_users_:rooPuzzlerDevil:}',
	'jctf{one_flag_to_rule_them_all_one_flag_to_find_them}',
	'jctf{one_flag_to_bring_them_all_and_in_the_darkness_bind_them}',
	'jctf{a_hacker_is_just_someone_that_wears_a_hoodie_on_the_internet}',
	'jctf{fake_flags_phobia_is_a_real_thing}',
	'jctf{you_dont_really_need_to_reverse_the_obfuscated_js}',
	'ictf{a_challenge_to_troll_people_using_adblockers_:rooDevil:}',
]
msg = ','.join(flags).encode()
key="""
			@keyframes spin {
				100% {
					transform: rotate(360deg);
				}
			}
			div {
				animation: spin 1s infinite;
				font-size: 144px;
				font-family: 'Comic Neue', sans-serif;
			}
		"""
print(b64encode(ARC4.new(key.encode()).encrypt(msg)).decode(), end="")
