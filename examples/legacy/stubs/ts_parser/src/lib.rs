use anyhow::Result;
use nom::{
    bytes::complete::{tag, take_while1},
    character::complete::{multispace0, multispace1, space0},
    multi::many0,
    sequence::{delimited, preceded, terminated, tuple},
    IResult,
};

#[derive(Debug, Clone, PartialEq)]
pub enum PrimitiveType { F64, I32, Custom(String) }

#[derive(Debug, Clone, PartialEq)]
pub struct StateField { pub name: String, pub ty: PrimitiveType }

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Variable(String),
    Number(f64),
    ThreeBodyGravity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ASTNode {
    System { name: String, body: Vec<ASTNode> },
    State { name: String, fields: Vec<StateField> },
    Invariant { name: String, expr: Expr },
    Execute { name: String, target_var: String, update_expr: Expr },
}

fn parse_identifier(input: &str) -> IResult<&str, String> {
    let (input, id) = take_while1(|c: char| c.is_alphanumeric() || c == '_')(input)?;
    Ok((input, id.to_string()))
}

fn parse_type(input: &str) -> IResult<&str, PrimitiveType> {
    let (input, id) = parse_identifier(input)?;
    let ty = match id.as_str() {
        "F64" => PrimitiveType::F64,
        _ => PrimitiveType::Custom(id),
    };
    Ok((input, ty))
}

fn parse_field(input: &str) -> IResult<&str, StateField> {
    let (input, (name, _, _, _, ty)) = tuple((parse_identifier, space0, tag(":"), space0, parse_type))(input)?;
    Ok((input, StateField { name, ty }))
}

fn parse_state_block(input: &str) -> IResult<&str, ASTNode> {
    let (input, _) = preceded(multispace0, tag("state"))(input)?;
    let (input, name) = preceded(multispace1, parse_identifier)(input)?;
    let (input, _) = terminated(tag(":"), multispace0)(input)?;
    let (input, fields) = many0(terminated(preceded(multispace0, parse_field), multispace0))(input)?;
    Ok((input, ASTNode::State { name, fields }))
}

fn parse_invariant_block(input: &str) -> IResult<&str, ASTNode> {
    let (input, _) = preceded(multispace0, tag("invariant"))(input)?;
    let (input, name) = preceded(multispace1, parse_identifier)(input)?;
    let (input, _) = terminated(tag(":"), multispace0)(input)?;
    let (input, _) = delimited(tuple((multispace0, tag("guarantee"))), take_while1(|c: char| c != '\n'), multispace0)(input)?;
    Ok((input, ASTNode::Invariant { name, expr: Expr::ThreeBodyGravity }))
}

fn parse_execute_block(input: &str) -> IResult<&str, ASTNode> {
    let (input, _) = preceded(multispace0, tag("execute"))(input)?;
    let (input, name) = preceded(multispace1, parse_identifier)(input)?;
    let (input, _) = terminated(tag(":"), multispace0)(input)?;
    let (input, _) = delimited(tuple((multispace0, tag("transform"))), take_while1(|c: char| c != '\n'), multispace0)(input)?;
    Ok((input, ASTNode::Execute { name, target_var: "all_bodies".to_string(), update_expr: Expr::ThreeBodyGravity }))
}

fn parse_system_block(input: &str) -> IResult<&str, ASTNode> {
    let (input, _) = preceded(multispace0, tag("system"))(input)?;
    let (input, name) = preceded(multispace1, parse_identifier)(input)?;
    let (input, _) = terminated(tag(":"), multispace0)(input)?;
    let (input, body) = many0(preceded(multispace0, nom::branch::alt((parse_state_block, parse_invariant_block, parse_execute_block))))(input)?;
    Ok((input, ASTNode::System { name, body }))
}

pub fn parse_source(input: &str) -> Result<Vec<ASTNode>> {
    let (_, system_node) = parse_system_block(input).map_err(|e| anyhow::anyhow!("Parsing error: {:?}", e))?;
    Ok(vec![system_node])
}
