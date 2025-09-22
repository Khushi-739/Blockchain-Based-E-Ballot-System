from django.shortcuts import render, redirect
from . import models
import math
from datetime import datetime
from django.contrib.admin.forms import AuthenticationForm
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
import datetime
from hashlib import sha512, sha256
from .merkleTree import merkleTree
from .xtra import *
from django.urls import reverse
from pytz import timezone
from django.contrib.auth.decorators import login_required

# Toggle: set True to allow anyone to register (open registration).
# Keep False to require usernames to be present in VoterList (whitelist mode).
OPEN_REGISTRATION = False


def home(request):
    error = False
    try:
        time = get_vote_auth()
        # safe check
        if not time.exists():
            raise ValueError("Voting period not configured")

        format = "%d/%m/%Y at %H:%M:%S %Z%z"
        asia_start = time[0].start.astimezone(timezone("Asia/Kolkata"))
        asia_end = time[0].end.astimezone(timezone('Asia/Kolkata'))
        context = {
            'error': error,
            'start': asia_start.strftime(format),
            'end': asia_end.strftime(format),
        }
    except Exception:
        error = True
        context = {
            'error': error
        }

    return render(request, 'poll/home.html', context)


def otp(request):
    if request.method == "POST":
        otp = request.POST.get('otp')
        username = request.POST.get('username')
        password = request.POST.get('password')
        password1 = request.POST.get('password1')

        # safer retrieval
        Voter = models.VoterList.objects.filter(username=username).first()
        if Voter is None:
            return render(request, 'poll/failure.html', {'fail': 'Invalid Username!'})

        fail = ''
        try:
            if int(otp) == int(Voter.otp):
                if password == password1:
                    if not models.Voter.objects.filter(username=username).exists():
                        d, n, e = keyGen()
                        phrase = passPhrase()
                        user = User.objects.create_user(username=username, password=password)

                        voter = models.Voter(username=username)
                        voter.public_key_n = n
                        voter.public_key_e = e
                        voter.has_voted = False

                        voterpvt = models.VoterPvt(username=username)
                        voterpvt.private_key_d, voterpvt.private_key_n, voterpvt.salt = encrypt(phrase, str(d), str(n))

                        # SMS wrapped to avoid crashing if Twilio not configured
                        try:
                            sms(Voter.ph_country_code + Voter.phone_number,
                                " DO NOT SHARE THIS PASSPHRASE WITH ANYONE! \n\nYour Secret Passphrase is " + phrase)
                        except Exception:
                            print("⚠️ SMS not sent (Twilio config missing or invalid).")

                        user.save()
                        voter.save()
                        voterpvt.save()
                        context = {
                            'code': phrase,
                        }

                        return render(request, 'poll/success.html/', context)
                    else:
                        fail = 'Voter Already Exists'
                else:
                    fail = 'Password MisMatch!'
            else:
                fail = 'OTP is Invalid'
        except ValueError:
            fail = 'OTP is Invalid'
        return render(request, 'poll/failure.html/', {'fail': fail})
    return redirect('home')


def register(request):
    """
    Improved register:
    - Checks vote auth exists
    - Case-insensitive lookup in VoterList (username__iexact)
    - Helpful error messages + console prints for debugging
    - OPEN_REGISTRATION toggle to bypass VoterList (set to True above)
    """
    time = get_vote_auth()
    # check vote auth exists
    if not time.exists():
        return render(request, 'poll/failure.html', {'fail': "Voting is not configured yet!"})

    format = "%d/%m/%Y at %H:%M:%S %Z%z"
    if time[0].end < datetime.datetime.now(datetime.timezone.utc):
        asia = time[0].end.astimezone(timezone('Asia/Kolkata'))
        context = {
            'fail': "Cannot Register! Voting ended on " + asia.strftime(format),
        }
        return render(request, 'poll/failure.html', context)

    if request.method == 'POST':
        username = request.POST.get('username')
        if username is None:
            return render(request, 'poll/failure.html', {'fail': 'No username provided.'})

        # Debug: print username and incoming POST keys so you can confirm what the form submits
        print("DEBUG: register() called. submitted username:", username)
        print("DEBUG: POST keys:", list(request.POST.keys()))

        # If open registration is enabled, treat all usernames as valid
        if OPEN_REGISTRATION:
            validVoter = True
        else:
            # Case-insensitive match to avoid "Alice" vs "alice" mismatches
            validVoter = models.VoterList.objects.filter(username__iexact=username).exists()

        Registered = models.Voter.objects.filter(username__iexact=username).exists()

        if validVoter:
            if not Registered:
                # get VoterList entry using case-insensitive lookup
                voter = models.VoterList.objects.filter(username__iexact=username).first()

                # If OPEN_REGISTRATION is True and voter is None, create a temp object-like dict
                if voter is None and OPEN_REGISTRATION:
                    # Create a lightweight object with required attributes for the rest of the flow
                    class TempVoter:
                        def __init__(self, username):
                            self.username = username
                            self.ph_country_code = ''
                            self.phone_number = ''
                            self.otp = ''
                    voter = TempVoter(username)

                if voter is None:
                    # Provide helpful suggestions: similar usernames in VoterList
                    suggestions = list(models.VoterList.objects.filter(username__icontains=username).values_list('username', flat=True)[:5])
                    suggestion_msg = " Did you mean: {}?".format(", ".join(suggestions)) if suggestions else ""
                    print(f"DEBUG: VoterList lookup failed for '{username}'. suggestions: {suggestions}")
                    return render(request, 'poll/failure.html', {'fail': 'Invalid Voter!' + suggestion_msg})

                otp_number = otp_gen()
                # If voter model has phone fields empty (open mode), still save otp to DB only if real record
                try:
                    voter.otp = otp_number
                    voter.save()
                except Exception:
                    # voter might be TempVoter in OPEN_REGISTRATION, skip save
                    print("DEBUG: voter.save() skipped (open registration / temp voter).")

                # SMS wrapped
                try:
                    # Only attempt SMS if phone fields appear non-empty
                    if getattr(voter, 'ph_country_code', '') and getattr(voter, 'phone_number', ''):
                        sms(voter.ph_country_code + voter.phone_number, "Your OTP is " + str(otp_number))
                    else:
                        print("DEBUG: SMS skipped because phone number is missing for voter:", username)
                except Exception as e:
                    print("⚠️ OTP SMS not sent (Twilio config missing or invalid). Exception:", e)

                context = {
                    'username': username,
                    'country_code': getattr(voter, 'ph_country_code', ''),
                    'starred': ("*******" + str(getattr(voter, 'phone_number', ''))[-3:]) if getattr(voter, 'phone_number', '') else "*******",
                }
                return render(request, 'registration/otp.html/', context)

            return render(request, 'poll/failure.html', {'fail': 'Voter is Already Registered!'})

        else:
            # helpful diagnostic output
            print("DEBUG: Voter not found in VoterList for username:", username)
            # list up to 5 candidates that partially match
            close_matches = list(models.VoterList.objects.filter(username__icontains=username).values_list('username', flat=True)[:5])
            suggestion_text = ""
            if close_matches:
                suggestion_text = " Did you mean: " + ", ".join(close_matches) + " ?"
            return render(request, 'poll/failure.html', {'fail': 'Invalid Voter!' + suggestion_text})
    return render(request, 'registration/register.html/')


@login_required(login_url='login')
def vote(request):
    candidates = models.Candidate.objects.all()
    context = {'candidates': candidates}
    return render(request, 'poll/vote.html', context)


def signin(request):
    time = get_vote_auth()
    # ensure time exists
    if not time.exists():
        return render(request, 'poll/failure.html', {'fail': "Voting is not configured yet!"})

    now = datetime.datetime.now(datetime.timezone.utc)
    if time[0].end > now and time[0].start < now:
        if request.method == 'POST':
            # AuthenticationForm expects request parameter normally; you were passing POST
            # Keep your original flow but use posted username/password directly
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(username=username, password=password)
            if user:
                if user.is_active:
                    login(request, user)
                    return redirect(reverse('vote'))
            else:
                return render(request, 'poll/failure.html', {'fail': 'Invalid Credentials! Try Logging In Again.'})
        else:
            form = AuthenticationForm()
        return render(request, 'registration/login.html', {'form': form})
    else:
        format = "%d/%m/%Y at %H:%M:%S %Z%z"
        if time[0].end < datetime.datetime.now(datetime.timezone.utc):
            asia = time[0].end.astimezone(timezone('Asia/Kolkata'))
            context = {
                'fail': "Voting ended on " + asia.strftime(format),
            }
        elif time[0].start > datetime.datetime.now(datetime.timezone.utc):
            asia = time[0].start.astimezone(timezone("Asia/Kolkata"))
            context = {
                'fail': "Voting will start on " + asia.strftime(format),
            }
        return render(request, 'poll/failure.html', context)


@login_required(login_url='login')
def create(request, pk):
    # safe retrieval of voter
    voter = models.Voter.objects.filter(username=request.user.username).first()
    if voter is None:
        logout(request)
        return render(request, 'poll/failure.html', {'fail': 'Voter record not found. Please login again.'})

    if request.method == 'POST' and request.user.is_authenticated and not voter.has_voted:
        vote = pk
        lenVoteList = len(models.Vote.objects.all())
        if (lenVoteList > 0):
            block_id = math.floor(lenVoteList / 5) + 1
        else:
            block_id = 1

        phrase = request.POST.get('phrase')
        username = request.user.username

        voterpvt_qs = models.VoterPvt.objects.filter(username=username).values()
        if not voterpvt_qs:
            logout(request)
            return render(request, 'poll/failure.html', {'fail': 'Private key not found. Please login again.'})

        try:
            privateKey_d, privateKey_n = decrypt(
                phrase,
                voterpvt_qs[0]['private_key_d'],
                voterpvt_qs[0]['private_key_n'],
                voterpvt_qs[0]['salt']
            )
        except Exception:
            logout(request)
            return render(request, 'poll/failure.html', {'fail': 'Invalid Passphrase Please Login And Vote Again.'})

        priv_key = {'n': int(privateKey_n), 'd': int(privateKey_d)}
        pub_key = {'n': int(voter.public_key_n), 'e': int(voter.public_key_e)}
        timestamp = datetime.datetime.now().timestamp()
        ballot = "{}|{}".format(vote, timestamp)
        h = int.from_bytes(sha512(ballot.encode()).digest(), byteorder='big')
        signature = pow(h, priv_key['d'], priv_key['n'])

        hfromSignature = pow(signature, pub_key['e'], pub_key['n'])

        if (hfromSignature == h):
            new_vote = models.Vote(vote=pk)
            new_vote.block_id = block_id
            voter.has_voted = True
            voter.save()
            new_vote.save()
            status = 'Ballot signed successfully'
        else:
            logout(request)
            return render(request, 'poll/failure.html', {'fail': 'Signature verification failed.'})

        context = {
            'ballot': ballot,
            'signature': signature,
            'status': status,
            'id': new_vote.id
        }
        return render(request, 'poll/status.html', context)
    logout(request)
    return render(request, 'poll/failure.html', {'fail': 'It appears you have already voted!'})


@login_required(login_url='login')
def seal(request):

    if request.method == 'POST':
        vote_id = request.POST.get('vote_id')
        if (len(models.Vote.objects.all()) % 5 != 0):
            logout(request)
            return render(request, 'poll/votesuccess.html', {'code': vote_id})
        else:
            transactions = models.Vote.objects.order_by('block_id').reverse()
            transactions = list(transactions)[:5]
            block_id = transactions[0].block_id

            str_transactions = [str(x) for x in transactions]

            merkle_tree = merkleTree.merkleTree()
            merkle_tree.makeTreeFromArray(str_transactions)
            merkle_hash = merkle_tree.calculateMerkleRoot()

            nonce = 0
            timestamp = datetime.datetime.now().timestamp()

            vote_auth = models.VoteAuth.objects.get(username='admin')
            prev_hash = vote_auth.prev_hash
            while True:
                self_hash = sha256('{}{}{}{}'.format(prev_hash, merkle_hash, nonce, timestamp).encode()).hexdigest()
                if self_hash[0] == '0':
                    break
                nonce += 1
            vote_auth.prev_hash = self_hash
            vote_auth.save()
            block = models.Block(id=block_id, prev_hash=prev_hash, self_hash=self_hash, merkle_hash=merkle_hash, nonce=nonce, timestamp=timestamp)
            block.save()
            print('Block {} has been mined'.format(block_id))
            logout(request)
            return render(request, 'poll/votesuccess.html', {'code': vote_id})
    logout(request)
    return redirect("home")


def retDate(v):
    v.timestamp = datetime.datetime.fromtimestamp(v.timestamp)
    return v


def verify(request):
    time = get_vote_auth()
    # check vote auth exists
    if not time.exists():
        return render(request, 'poll/failure.html', {'fail': "Voting is not configured yet!"})

    if time[0].end < datetime.datetime.now(datetime.timezone.utc):
        if request.method == 'GET':
            verification = ''
            tampered_block_list = verifyVotes()
            votes = []
            if tampered_block_list:
                verification = 'Verification Failed. Following blocks have been tampered --> {}.\
                    The authority will resolve the issue'.format(tampered_block_list)
                error = True
            else:
                verification = 'Verification successful. All votes are intact!'
                error = False
                votes = models.Vote.objects.order_by('timestamp')
                votes = [retDate(x) for x in votes]

            context = {'verification': verification, 'error': error, 'votes': votes}
            return render(request, 'poll/verification.html', context)
        if request.method == 'POST':
            unique_id = request.POST.get('unique_id')
            try:
                tampered_block_list = verifyVotes()
                if tampered_block_list:
                    verification = 'Verification Failed. Following blocks have been tampered --> {}.\
                    The authority will resolve the issue'.format(tampered_block_list)
                    error = True
                else:
                    verification = 'Verification successful. The Vote is intact!'
                    error = False
                    vote = models.Vote.objects.filter(id=unique_id)
                    vote = [retDate(x) for x in vote]
            except Exception:
                vote = []
                error = True
                verification = 'Invalid Unique ID'
            context = {'verification': verification, 'error': error, 'votes': vote}
            return render(request, 'poll/verification.html', context)
    else:
        format = "%d/%m/%Y at %H:%M:%S %Z%z"
        asia = time[0].end.astimezone(timezone('Asia/Kolkata'))
        context = {
            'fail': "Verification will enable on " + asia.strftime(format),
        }
        return render(request, 'poll/failure.html', context)


def result(request):
    time = get_vote_auth()
    # check vote auth exists
    if not time.exists():
        return render(request, 'poll/failure.html', {'fail': "Voting is not configured yet!"})

    if time[0].end < datetime.datetime.now(datetime.timezone.utc):
        if request.method == "GET":
            voteVerification = verifyVotes()
            if len(voteVerification):
                return render(request, 'poll/verification.html', {'verification': "Verification failed.\
                    Votes have been tampered in following blocks --> {}. The authority \
                        will resolve the issue".format(voteVerification), 'error': True})

            vote_auth = models.VoteAuth.objects.get(username='admin')
            resultCalculated = vote_auth.resultCalculated
            if not resultCalculated:
                vote_auth.resultCalculated = True
                vote_auth.save()
                list_of_votes = models.Vote.objects.all()
                for vote in list_of_votes:
                    candidate = models.Candidate.objects.filter(candidateID=vote.vote).first()
                    if candidate:
                        candidate.count += 1
                        candidate.save()

            candidates_qs = models.Candidate.objects.order_by('count')
            winner = None
            try:
                winner = models.Candidate.objects.order_by('count').reverse()[0]
            except Exception:
                # no candidates
                winner = None

            context = {"candidates": candidates_qs, "winner": winner}
            return render(request, 'poll/results.html', context)
    else:
        format = "%d/%m/%Y at %H:%M:%S %Z%z"
        asia = time[0].end.astimezone(timezone('Asia/Kolkata'))
        context = {
            'fail': "Result will be displayed after " + asia.strftime(format),
        }
        return render(request, 'poll/failure.html', context)


def verifyVotes():
    block_count = models.Block.objects.count()
    tampered_block_list = []
    for i in range(1, block_count + 1):
        block = models.Block.objects.get(id=i)
        transactions = models.Vote.objects.filter(block_id=i)
        str_transactions = [str(x) for x in transactions]

        merkle_tree = merkleTree.merkleTree()
        merkle_tree.makeTreeFromArray(str_transactions)
        merkle_tree.calculateMerkleRoot()

        if (block.merkle_hash == merkle_tree.getMerkleRoot()):
            continue
        else:
            tampered_block_list.append(i)

    return tampered_block_list
