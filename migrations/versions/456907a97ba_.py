"""empty message

Revision ID: 456907a97ba
Revises: None
Create Date: 2014-07-27 21:55:03.918841

"""

# revision identifiers, used by Alembic.
revision = '456907a97ba'
down_revision = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=128), nullable=True),
    sa.Column('password', sa.String(length=60), nullable=True),
    sa.Column('active', sa.Boolean(), nullable=True),
    sa.Column('authenticated', sa.Boolean(), nullable=True),
    sa.Column('companion_key', sa.LargeBinary(length=32), nullable=True),
    sa.Column('user_key_salt', sa.LargeBinary(length=32), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_email'), 'user', ['email'], unique=True)
    op.create_table('post',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('meta', sa.Text(), nullable=True),
    sa.Column('body', sa.LargeBinary(), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('post')
    op.drop_index(op.f('ix_user_email'), table_name='user')
    op.drop_table('user')
    ### end Alembic commands ###